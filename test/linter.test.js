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

test('explicit-root-user flags root in every spelling', () => {
  // string "root", bare numeric 0 (YAML unquoted), and "0:0" all resolve to
  // uid 0 — each fires once, as a warn.
  const yaml = [
    'services:',
    '  a:',
    '    image: alpine:3.20',
    '    user: root',
    '  b:',
    '    image: alpine:3.20',
    '    user: 0',
    '  c:',
    '    image: alpine:3.20',
    '    user: "0:0"',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'explicit-root-user');
  assert.equal(hits.length, 3);
  assert.ok(hits.every((f) => f.level === 'warn'));
});

test('explicit-root-user spares non-root users, the root group alone, and interpolations', () => {
  // "1000:0" is the OpenShift arbitrary-uid pattern (root GROUP, not root),
  // and ${APP_UID} comes from outside the file — neither is provably root.
  // A service with no user: line stays quiet too (the image's USER is unknown).
  const yaml = [
    'services:',
    '  a:',
    '    image: alpine:3.20',
    '    user: "1000:1000"',
    '  b:',
    '    image: alpine:3.20',
    '    user: node',
    '  c:',
    '    image: alpine:3.20',
    '    user: "1000:0"',
    '  d:',
    '    image: alpine:3.20',
    '    user: ${APP_UID}',
    '  e:',
    '    image: alpine:3.20',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'explicit-root-user');
  assert.equal(hits.length, 0);
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

test('dangerous-device: raw disks, kernel memory and /dev are errors; kmsg warns', () => {
  const yaml = [
    'services:',
    '  x:',
    '    image: alpine:3.20',
    '    devices:',
    '      - /dev/sda:/dev/sda',
    '      - /dev/nvme0n1p2:/dev/nvme0n1p2',
    '      - /dev/mapper/vg0-root:/dev/mapper/vg0-root',
    '      - /dev/mem:/dev/mem',
    '      - /dev:/dev',
    '      - /dev/kmsg:/dev/kmsg',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'dangerous-device');
  assert.equal(found.length, 6);
  assert.equal(found.filter((f) => f.level === 'error').length, 5);
  assert.ok(found.some((f) => f.message.includes('/dev/kmsg') && f.level === 'warn'));
});

test('dangerous-device: :r does not soften a raw disk, and the hint says so', () => {
  const yaml = [
    'services:',
    '  x:',
    '    image: alpine:3.20',
    '    devices:',
    '      - /dev/sda:/dev/sda:r',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'dangerous-device');
  assert.equal(found.length, 1);
  assert.equal(found[0].level, 'error');
  assert.match(found[0].hint, /:r/);
});

test('dangerous-device spares purpose-built nodes, bare-path form and CDI names', () => {
  const yaml = [
    'services:',
    '  x:',
    '    image: alpine:3.20',
    '    devices:',
    '      - /dev/dri:/dev/dri',
    '      - /dev/snd:/dev/snd',
    '      - /dev/net/tun:/dev/net/tun',
    '      - /dev/ttyUSB0:/dev/ttyUSB0',
    '      - /dev/fuse',
    '      - nvidia.com/gpu=all',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'dangerous-device');
  assert.equal(found.length, 0);
});

test('shared-namespace: pid/ipc container-sharing and ipc:shareable each warn', () => {
  const yaml = [
    'services:',
    '  a:',
    '    image: alpine:3.20',
    '    pid: "service:victim"',
    '    ipc: "container:victim"',
    '  b:',
    '    image: alpine:3.20',
    '    ipc: shareable',
    '  victim:',
    '    image: alpine:3.20',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'shared-namespace');
  // a: two findings (pid + ipc), b: one (shareable) = 3
  assert.equal(found.length, 3);
  assert.ok(found.some((f) => f.service === 'a' && /process \(PID\) namespace/.test(f.message)));
  assert.ok(found.some((f) => f.service === 'a' && /IPC namespace/.test(f.message)));
  assert.ok(found.some((f) => f.service === 'b' && /shareable/.test(f.message)));
});

test('shared-namespace spares host (host-namespace owns it), private/none, and network_mode', () => {
  const yaml = [
    'services:',
    '  x:',
    '    image: alpine:3.20',
    '    pid: host',              // host-namespace's job, not this rule's
    '    ipc: none',              // fine
    '    network_mode: "service:y"',  // the network rules own network_mode
    '  y:',
    '    image: alpine:3.20',
    '    ipc: private',           // the default, fine
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'shared-namespace');
  assert.equal(found.length, 0);
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

test('duplicate-mount-target flags two mounts on one path, trailing slash included', () => {
  // The daemon refuses the container at create ("Duplicate mount point") —
  // and it normalizes trailing slashes before comparing, so /x and /x/ are
  // the same mount point (both verified against a real daemon).
  const yaml = [
    'services:',
    '  a:',
    '    image: nginx:1.27',
    '    volumes:',
    '      - data:/var/lib/app',
    '      - backup:/var/lib/app/',
    'volumes:',
    '  data:',
    '  backup:',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'duplicate-mount-target');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].level, 'error');
  assert.match(hits[0].message, /Duplicate mount point/);
});

test('duplicate-mount-target sees tmpfs entries and long-form volumes collide too', () => {
  // tmpfs+volume dies at the daemon like any other pair; the tmpfs entry
  // keeps its options, the long form spells the target under `target:`.
  const yaml = [
    'services:',
    '  a:',
    '    image: nginx:1.27',
    '    tmpfs:',
    '      - /run/app:size=64m',
    '    volumes:',
    '      - type: volume',
    '        source: data',
    '        target: /run/app',
    'volumes:',
    '  data:',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'duplicate-mount-target');
  assert.equal(hits.length, 1);
});

test('duplicate-mount-target spares distinct targets, shared sources, and other services', () => {
  // The same volume mounted at two different paths is legal (and useful);
  // mount namespaces are per container, so another service reusing the path
  // is no conflict either.
  const yaml = [
    'services:',
    '  a:',
    '    image: nginx:1.27',
    '    tmpfs: /run/app',
    '    volumes:',
    '      - data:/var/lib/app',
    '      - data:/mnt/same-volume-elsewhere',
    '  b:',
    '    image: nginx:1.27',
    '    volumes:',
    '      - data:/var/lib/app',
    'volumes:',
    '  data:',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'duplicate-mount-target');
  assert.equal(hits.length, 0);
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
    'dangerous-cap', 'sensitive-host-mount', 'dangerous-device', 'shared-namespace', 'no-new-privileges',
    'env-secret', 'secret-empty-when-unset', 'port-public', 'security-unconfined', 'build-arg-secret', 'command-secret',
    'mem-reservation-exceeds-limit', 'ulimit-soft-exceeds-hard', 'zero-limit-is-unlimited',
    'port-conflict', 'duplicate-container-name', 'depends-on-unknown',
    'depends-on-ignores-healthcheck', 'undeclared-network', 'undeclared-volume',
    'container-name-with-replicas', 'healthcheck-no-start-period',
    'service-healthy-no-healthcheck', 'healthcheck-test-invalid',
    'duplicate-env-key', 'undeclared-secret', 'ports-with-host-network',
    'explicit-root-user', 'duplicate-mount-target', 'network-mode-with-networks',
    'oom-kill-disable', 'ports-on-internal-network',
    'healthcheck-timeout-exceeds-interval',
  ]) {
    assert.ok(rules.has(r), `expected rule '${r}'`);
  }
});

test('network-mode-with-networks flags the mutually exclusive pair for any mode', () => {
  // Compose refuses the whole file ("declares mutually exclusive
  // `network_mode` and `networks`: invalid compose project") — host,
  // bridge and service: modes all die identically (verified live).
  for (const mode of ['host', 'bridge', 'service:db']) {
    const yaml = [
      'services:',
      '  db:',
      '    image: postgres:16',
      '  app:',
      '    image: nginx:1.27',
      `    network_mode: ${mode}`,
      '    networks:',
      '      - backend',
      'networks:',
      '  backend:',
    ].join('\n');
    const hits = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'network-mode-with-networks');
    assert.equal(hits.length, 1, `expected one hit for mode ${mode}`);
    assert.equal(hits[0].level, 'error');
    assert.equal(hits[0].service, 'app');
  }
});

test('network-mode-with-networks spares an empty networks list and either key alone', () => {
  // `networks: []` passes `docker compose config` (verified live) — only a
  // non-empty list collides with network_mode.
  const emptyList = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    network_mode: host',
    '    networks: []',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(emptyList)).findings.some((f) => f.rule === 'network-mode-with-networks'));

  const modeOnly = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    network_mode: host',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(modeOnly)).findings.some((f) => f.rule === 'network-mode-with-networks'));

  const networksOnly = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    networks:',
    '      - backend',
    'networks:',
    '  backend:',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(networksOnly)).findings.some((f) => f.rule === 'network-mode-with-networks'));
});

test('network-mode-with-networks sees the map form of networks too', () => {
  const yaml = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    network_mode: none',
    '    networks:',
    '      backend:',
    '        aliases:',
    '          - app.internal',
    'networks:',
    '  backend:',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'network-mode-with-networks');
  assert.equal(hits.length, 1);
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

// --- ports-on-internal-network (v0.35) ----------------------------------------

test('ports-on-internal-network fires when every joined network is internal', () => {
  const compose = [
    'services:',
    '  web:',
    '    image: nginx:1.27',
    '    ports:',
    '      - "127.0.0.1:8099:80"',
    '      - "8443:443"',
    '    networks: [locked]',
    'networks:',
    '  locked:',
    '    internal: true',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(compose)).findings.filter((f) => f.rule === 'ports-on-internal-network');
  assert.equal(hits.length, 1, 'one finding per service, not per mapping');
  assert.equal(hits[0].service, 'web');
  assert.equal(hits[0].level, 'warn');
  assert.match(hits[0].message, /2 port mappings/);
  assert.match(hits[0].message, /locked/);
});

test('ports-on-internal-network stays quiet when one joined network is not internal', () => {
  // Verified live: one non-internal network restores the binding (HTTP 200).
  const compose = [
    'services:',
    '  web:',
    '    image: nginx:1.27',
    '    ports:',
    '      - "127.0.0.1:8099:80"',
    '    networks: [locked, open]',
    'networks:',
    '  locked:',
    '    internal: true',
    '  open: {}',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(compose)).findings.some((f) => f.rule === 'ports-on-internal-network'));
});

test('ports-on-internal-network judges the implicit default network when the file makes it internal', () => {
  const noNetworksKey = [
    'services:',
    '  web:',
    '    image: nginx:1.27',
    '    ports:',
    '      - "8080:80"',
    'networks:',
    '  default:',
    '    internal: true',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(noNetworksKey)).findings.filter((f) => f.rule === 'ports-on-internal-network');
  assert.equal(hits.length, 1);
  assert.match(hits[0].message, /default/);

  // Plain implicit default (not declared internal) stays quiet.
  const plain = [
    'services:',
    '  web:',
    '    image: nginx:1.27',
    '    ports:',
    '      - "8080:80"',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(plain)).findings.some((f) => f.rule === 'ports-on-internal-network'));
});

test('ports-on-internal-network leaves ghosts and network_mode to their own rules', () => {
  // `backend` is undeclared: its internal flag is unknowable, so this rule
  // stays quiet and undeclared-network owns the finding.
  const ghost = [
    'services:',
    '  web:',
    '    image: nginx:1.27',
    '    ports:',
    '      - "8080:80"',
    '    networks: [backend]',
    'networks:',
    '  locked:',
    '    internal: true',
  ].join('\n');
  const ghostFindings = DS.lint(DS.parseCompose(ghost)).findings;
  assert.ok(!ghostFindings.some((f) => f.rule === 'ports-on-internal-network'));
  assert.ok(ghostFindings.some((f) => f.rule === 'undeclared-network'));

  // host networking's dead ports belong to ports-with-host-network.
  const hostMode = [
    'services:',
    '  agent:',
    '    image: prom/node-exporter:v1.8.2',
    '    network_mode: host',
    '    ports:',
    '      - "9100:9100"',
    'networks:',
    '  locked:',
    '    internal: true',
  ].join('\n');
  const hostFindings = DS.lint(DS.parseCompose(hostMode)).findings;
  assert.ok(!hostFindings.some((f) => f.rule === 'ports-on-internal-network'));
  assert.ok(hostFindings.some((f) => f.rule === 'ports-with-host-network'));
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

test('oom-kill-disable: error with no memory limit, warn when a limit exists', () => {
  // Verified against a real daemon: on cgroups v2 the flag is DISCARDED
  // with a warning; on v1 without a limit a leak hangs the host.
  const bare = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    oom_kill_disable: true',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(bare)).findings.filter((f) => f.rule === 'oom-kill-disable');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].level, 'error');

  const limited = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    oom_kill_disable: true',
    '    mem_limit: 512m',
  ].join('\n');
  const hits2 = DS.lint(DS.parseCompose(limited)).findings.filter((f) => f.rule === 'oom-kill-disable');
  assert.equal(hits2.length, 1);
  assert.equal(hits2[0].level, 'warn');

  // The modern limit spelling counts the same as the legacy one.
  const deployLimited = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    oom_kill_disable: true',
    '    deploy:',
    '      resources:',
    '        limits:',
    '          memory: 512M',
  ].join('\n');
  assert.equal(
    DS.lint(DS.parseCompose(deployLimited)).findings.filter((f) => f.rule === 'oom-kill-disable')[0].level,
    'warn',
  );
});

test('oom-kill-disable stays quiet when absent or explicitly false', () => {
  const absent = ['services:', '  app:', '    image: nginx:1.27'].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(absent)).findings.some((f) => f.rule === 'oom-kill-disable'));
  const explicit = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    oom_kill_disable: false',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(explicit)).findings.some((f) => f.rule === 'oom-kill-disable'));
});

// --- depends-on-profile-gated (v0.34) ---------------------------------------

test('depends-on-profile-gated fires when an ungated service depends on a gated one', () => {
  const yml = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    depends_on: [db]',
    '  db:',
    '    image: postgres:16',
    '    profiles: [extra]',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(yml)).findings.filter((f) => f.rule === 'depends-on-profile-gated');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].service, 'app');
  assert.equal(hits[0].level, 'warn');
  assert.match(hits[0].message, /depends on undefined service/);
});

test('depends-on-profile-gated fires when the profiles do not cover the dep', () => {
  // app runs under `web`; db only exists under `extra` — `--profile web` dies.
  const yml = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    profiles: [web]',
    '    depends_on: [db]',
    '  db:',
    '    image: postgres:16',
    '    profiles: [extra]',
  ].join('\n');
  assert.equal(
    DS.lint(DS.parseCompose(yml)).findings.filter((f) => f.rule === 'depends-on-profile-gated').length,
    1,
  );
});

test('depends-on-profile-gated stays quiet when the dependent profiles are a subset', () => {
  // Every run that enables app (profile extra) also enables db.
  const yml = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    profiles: [extra]',
    '    depends_on: [db]',
    '  db:',
    '    image: postgres:16',
    '    profiles: [extra, other]',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(yml)).findings.some((f) => f.rule === 'depends-on-profile-gated'));
});

test('depends-on-profile-gated stays quiet for ungated deps and leaves dangling names alone', () => {
  const quiet = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    depends_on: [db]',
    '  db:',
    '    image: postgres:16',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(quiet)).findings.some((f) => f.rule === 'depends-on-profile-gated'));

  // A dangling name is depends-on-unknown's finding, never this one.
  const dangling = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    depends_on: [ghost]',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(dangling)).findings;
  assert.ok(found.some((f) => f.rule === 'depends-on-unknown'));
  assert.ok(!found.some((f) => f.rule === 'depends-on-profile-gated'));
});

test('healthcheck-timeout-exceeds-interval fires when the probe can outlast its own cycle', () => {
  const compose = [
    'services:',
    '  slow:',
    '    image: postgres:16',
    '    healthcheck:',
    '      test: ["CMD-SHELL", "pg_isready"]',
    '      interval: 2s',
    '      timeout: 6s',
    '      retries: 3',
    '      start_period: 10s',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(compose)).findings
    .filter((f) => f.rule === 'healthcheck-timeout-exceeds-interval');
  assert.equal(found.length, 1);
  assert.equal(found[0].level, 'warn');
  // The message must carry the real numbers: the stretched cycle (timeout +
  // interval) and the worst-case time to notice (retries x that). Measured
  // against a real daemon with exactly these values: 26.1s.
  assert.match(found[0].message, /pause BETWEEN probes/);
  assert.match(found[0].message, /8s/);
  assert.match(found[0].message, /24s/);
});

test('healthcheck-timeout-exceeds-interval is quiet when the timeout fits, equals, or is unreadable', () => {
  const compose = [
    'services:',
    '  fits:',
    '    image: postgres:16',
    '    healthcheck:',
    '      test: ["CMD-SHELL", "pg_isready"]',
    '      interval: 30s',
    '      timeout: 5s',
    '  equal:',
    '    image: postgres:16',
    '    healthcheck:',
    '      test: ["CMD-SHELL", "pg_isready"]',
    '      interval: 10s',
    '      timeout: 10s',
    '  interpolated:',
    '    image: postgres:16',
    '    healthcheck:',
    '      test: ["CMD-SHELL", "pg_isready"]',
    '      interval: 5s',
    '      timeout: ${HC_TIMEOUT}',
    '  disabled:',
    '    image: postgres:16',
    '    healthcheck:',
    '      disable: true',
    '      interval: 1s',
    '      timeout: 30s',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(compose)).findings
    .filter((f) => f.rule === 'healthcheck-timeout-exceeds-interval');
  assert.equal(found.length, 0);
});

test('healthcheck-timeout-exceeds-interval reads compound and sub-second durations', () => {
  const compose = [
    'services:',
    '  compound:',
    '    image: redis:7',
    '    healthcheck:',
    '      test: ["CMD", "redis-cli", "ping"]',
    '      interval: 1m',
    '      timeout: 1m30s',
    '  subsecond:',
    '    image: redis:7',
    '    healthcheck:',
    '      test: ["CMD", "redis-cli", "ping"]',
    '      interval: 500ms',
    '      timeout: 2s',
    '  bareseconds:',
    '    image: redis:7',
    '    healthcheck:',
    '      test: ["CMD", "redis-cli", "ping"]',
    '      interval: 5',
    '      timeout: 10',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(compose)).findings
    .filter((f) => f.rule === 'healthcheck-timeout-exceeds-interval');
  assert.equal(found.length, 3);
  const names = found.map((f) => f.service).sort();
  assert.equal(JSON.stringify(names), JSON.stringify(['bareseconds', 'compound', 'subsecond']));
});

test('port-public recognizes a sensitive container port even when the image name says nothing', () => {
  const compose = [
    'services:',
    // A private registry image: the name matches no known database pattern,
    // but the container port names the protocol all the same.
    '  corp-db:',
    '    image: registry.corp/team/api-db:7',
    '    ports:',
    '      - "5432:5432"',
    // The Docker API in plaintext is the worst of the set: remote root.
    '  dind:',
    '    image: docker:27-dind',
    '    ports:',
    '      - "2375:2375"',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(compose)).findings.filter((f) => f.rule === 'port-public');
  assert.equal(found.length, 2);
  assert.match(found[0].message, /`postgres` \(container port 5432\)/);
  assert.match(found[1].message, /`docker api \(plaintext — remote root\)` \(container port 2375\)/);
  // The point of the message: a host firewall in INPUT does not filter this.
  assert.match(found[0].message, /ufw included/);
});

test('port-public stays quiet for a pinned host IP, an ordinary port, and an unpublished one', () => {
  const compose = [
    'services:',
    '  pinned:',
    '    image: registry.corp/team/api-db:7',
    '    ports:',
    '      - "127.0.0.1:5432:5432"',
    '  lan-pinned:',
    '    image: registry.corp/team/api-db:7',
    '    ports:',
    '      - "10.0.0.5:5432:5432"',
    '  web:',
    '    image: registry.corp/team/frontend:2',
    '    ports:',
    '      - "8080:80"',
    '  internal-only:',
    '    image: registry.corp/team/api-db:7',
    '    expose:',
    '      - "5432"',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(compose)).findings.filter((f) => f.rule === 'port-public');
  assert.equal(found.length, 0);
});

// --- restart-not-a-string (v0.37) ----------------------------------------

test('restart: false (a YAML boolean) is an error - Compose rejects the file', () => {
  const yaml = ['services:', '  app:', '    image: debian:13', '    restart: false'].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  const rules = new Set(findings.map((f) => f.rule));
  assert.ok(rules.has('restart-not-a-string'), 'boolean restart → error');
  // ...and it does NOT also nag about a missing policy: one message, not two.
  assert.ok(!rules.has('no-restart'), 'no double report with no-restart');
});

test('the unquoted word `no` is the STRING "no" and is accepted (YAML 1.2)', () => {
  const yaml = ['services:', '  app:', '    image: debian:13', '    restart: no'].join('\n');
  const model = DS.parseCompose(yaml);
  assert.equal(model.services[0].restart, 'no');
  const rules = new Set(DS.lint(model).findings.map((f) => f.rule));
  assert.ok(!rules.has('restart-not-a-string'), 'string "no" is valid');
  assert.ok(!rules.has('no-restart'), 'a policy IS set');
});

// --- restart-no-with-healthcheck (v0.37) ---------------------------------

test('restart "no" + a healthcheck nobody consumes is flagged', () => {
  const yaml = [
    'services:',
    '  worker:',
    '    image: registry.corp/team/worker:3',
    '    restart: "no"',
    '    healthcheck:',
    '      test: ["CMD", "true"]',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  assert.ok(findings.some((f) => f.rule === 'restart-no-with-healthcheck' && f.level === 'warn'));
});

test('a service_healthy dependent spares restart "no" + healthcheck', () => {
  const yaml = [
    'services:',
    '  db:',
    '    image: registry.corp/team/api-db:7',
    '    restart: "no"',
    '    healthcheck:',
    '      test: ["CMD", "true"]',
    '  app:',
    '    image: registry.corp/team/api:2',
    '    depends_on:',
    '      db:',
    '        condition: service_healthy',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'restart-no-with-healthcheck');
  assert.equal(found.length, 0, 'a consumer of the health signal spares it');
});

test('restart "no" without a healthcheck never fires (nothing to watch)', () => {
  const yaml = ['services:', '  job:', '    image: registry.corp/team/job:1', '    restart: "no"'].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'restart-no-with-healthcheck');
  assert.equal(found.length, 0);
});

test('a disabled healthcheck under restart "no" does not fire (no signal exists)', () => {
  const yaml = [
    'services:',
    '  job:',
    '    image: registry.corp/team/job:1',
    '    restart: "no"',
    '    healthcheck:',
    '      test: ["NONE"]',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'restart-no-with-healthcheck');
  assert.equal(found.length, 0);
});

test('restart always + healthcheck is fine - the policy consumes nothing but is not "no"', () => {
  const yaml = [
    'services:',
    '  svc:',
    '    image: registry.corp/team/svc:1',
    '    restart: always',
    '    healthcheck:',
    '      test: ["CMD", "true"]',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'restart-no-with-healthcheck');
  assert.equal(found.length, 0);
});

// --- sysctl-not-namespaced (v0.38) ----------------------------------------

test('vm.max_map_count in sysctls is an error - the container is never created', () => {
  const yaml = [
    'services:',
    '  search:',
    '    image: registry.corp/team/search:8',
    '    sysctls:',
    '      vm.max_map_count: 262144',
  ].join('\n');
  const rules = new Set(DS.lint(DS.parseCompose(yaml)).findings.map((f) => f.rule));
  assert.ok(rules.has('sysctl-not-namespaced'), 'vm.* is host-global');
  // ...and the host-namespace rule stays out of it: one finding, not two.
  assert.ok(!rules.has('sysctl-in-host-namespace'), 'no double report');
});

test('list-form sysctls are judged too (fs.file-max=...)', () => {
  const yaml = [
    'services:',
    '  app:',
    '    image: registry.corp/team/app:1',
    '    sysctls:',
    '      - fs.file-max=100000',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'sysctl-not-namespaced');
  assert.equal(found.length, 1);
  assert.equal(found[0].level, 'error');
});

test('the namespaced set is quiet: IPC, fs.mqueue.*, net.* and kernel.domainname', () => {
  const yaml = [
    'services:',
    '  tuned:',
    '    image: registry.corp/team/tuned:1',
    '    sysctls:',
    '      net.core.somaxconn: 1024',
    '      kernel.shmmax: 68719476736',
    '      kernel.sem: 250 32000 100 128',
    '      fs.mqueue.msg_max: 64',
    '      kernel.domainname: lab',
  ].join('\n');
  const rules = new Set(DS.lint(DS.parseCompose(yaml)).findings.map((f) => f.rule));
  assert.ok(!rules.has('sysctl-not-namespaced'), 'all five are namespaced');
  assert.ok(!rules.has('sysctl-in-host-namespace'), 'no host namespace in play');
});

test('interpolated sysctl keys are never judged - the value comes from outside the file', () => {
  const yaml = [
    'services:',
    '  app:',
    '    image: registry.corp/team/app:1',
    '    sysctls:',
    '      - ${EXTRA_SYSCTL}=1',
  ].join('\n');
  const rules = new Set(DS.lint(DS.parseCompose(yaml)).findings.map((f) => f.rule));
  assert.ok(!rules.has('sysctl-not-namespaced'));
});

// --- sysctl-in-host-namespace (v0.38) -------------------------------------

test('net.* sysctl under network_mode: host is an error - the namespace was given away', () => {
  const yaml = [
    'services:',
    '  edge:',
    '    image: registry.corp/team/edge:2',
    '    network_mode: host',
    '    sysctls:',
    '      net.core.somaxconn: 1024',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'sysctl-in-host-namespace');
  assert.equal(found.length, 1);
  assert.equal(found[0].level, 'error');
  assert.ok(found[0].message.includes('network_mode: host'));
});

test('net.* sysctl under network_mode: service:x is fine - the joined namespace is private', () => {
  const yaml = [
    'services:',
    '  base:',
    '    image: registry.corp/team/base:1',
    '  joined:',
    '    image: registry.corp/team/app:1',
    '    network_mode: service:base',
    '    sysctls:',
    '      net.core.somaxconn: 1024',
  ].join('\n');
  const rules = new Set(DS.lint(DS.parseCompose(yaml)).findings.map((f) => f.rule));
  assert.ok(!rules.has('sysctl-in-host-namespace'), 'only the literal host forfeits it');
});

test('IPC sysctls under ipc: host and kernel.domainname under uts: host both fire', () => {
  const yaml = [
    'services:',
    '  shm:',
    '    image: registry.corp/team/db:1',
    '    ipc: host',
    '    sysctls:',
    '      kernel.shmmax: 68719476736',
    '      fs.mqueue.msg_max: 64',
    '  named:',
    '    image: registry.corp/team/app:1',
    '    uts: host',
    '    sysctls:',
    '      kernel.domainname: lab',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'sysctl-in-host-namespace');
  assert.equal(found.length, 3, 'two IPC keys + one UTS key');
});

test('a host-global sysctl under network_mode: host reports once, as not-namespaced', () => {
  const yaml = [
    'services:',
    '  app:',
    '    image: registry.corp/team/app:1',
    '    network_mode: host',
    '    sysctls:',
    '      vm.overcommit_memory: 1',
  ].join('\n');
  const findings = DS.lint(DS.parseCompose(yaml)).findings;
  assert.equal(findings.filter((f) => f.rule === 'sysctl-not-namespaced').length, 1);
  assert.equal(findings.filter((f) => f.rule === 'sysctl-in-host-namespace').length, 0);
});

// --- ports-with-container-network-mode + network-mode-undefined-service (v0.39)

test('ports under service: network_mode is an error naming the daemon refusal and the owner', () => {
  const yaml = [
    'services:',
    '  vpn:',
    '    image: qmcgaw/gluetun:v3.39',
    '  app:',
    '    image: app:1',
    '    network_mode: service:vpn',
    '    ports:',
    '      - "8080:80"',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  const hits = findings.filter((f) => f.rule === 'ports-with-container-network-mode');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].service, 'app');
  assert.equal(hits[0].level, 'error');
  assert.match(hits[0].message, /port publishing and the container type network mode/);
  assert.match(hits[0].message, /`docker compose config` never warns/);
  assert.match(hits[0].hint, /Move the `ports:` to `vpn`/);
});

test('expose alone also dies under a container-type mode - the usually-inert key kills here', () => {
  const yaml = [
    'services:',
    '  app:',
    '    image: app:1',
    '    network_mode: container:external-vpn',
    '    expose:',
    '      - 9090',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  const hits = findings.filter((f) => f.rule === 'ports-with-container-network-mode');
  assert.equal(hits.length, 1);
  assert.match(hits[0].message, /port exposing and the container type network mode/);
  // container:<name> owns nothing in this file - the hint stays generic
  assert.match(hits[0].hint, /owns the network namespace/);
});

test('a host-port-less ports entry ("80") still counts - it publishes to an ephemeral port', () => {
  const yaml = [
    'services:',
    '  vpn:',
    '    image: vpn:1',
    '  app:',
    '    image: app:1',
    '    network_mode: service:vpn',
    '    ports:',
    '      - "80"',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  assert.equal(findings.filter((f) => f.rule === 'ports-with-container-network-mode').length, 1);
});

test('the correct VPN-sidecar pattern is quiet: ports on the namespace owner, none on the joiner', () => {
  const yaml = [
    'services:',
    '  vpn:',
    '    image: qmcgaw/gluetun:v3.39',
    '    ports:',
    '      - "8080:80"',
    '  app:',
    '    image: app:1',
    '    network_mode: service:vpn',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  assert.equal(findings.filter((f) => f.rule === 'ports-with-container-network-mode').length, 0);
  // and host mode stays the other rule's business (silent discard, not refusal)
  const host = ['services:', '  a:', '    image: a:1', '    network_mode: host', '    ports:', '      - "80:80"'].join('\n');
  const hostFindings = DS.lint(DS.parseCompose(host)).findings;
  assert.equal(hostFindings.filter((f) => f.rule === 'ports-with-container-network-mode').length, 0);
  assert.equal(hostFindings.filter((f) => f.rule === 'ports-with-host-network').length, 1);
});

test('network_mode: service:ghost is an error - a dependency in disguise, dead already at config', () => {
  const yaml = [
    'services:',
    '  app:',
    '    image: app:1',
    '    network_mode: service:ghost',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  const hits = findings.filter((f) => f.rule === 'network-mode-undefined-service');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].level, 'error');
  assert.match(hits[0].message, /depends on undefined service/);
  assert.match(hits[0].message, /never mentions network_mode/);
});

test('network-mode-undefined-service spares existing services, container: mode and interpolations', () => {
  const yaml = [
    'services:',
    '  vpn:',
    '    image: vpn:1',
    '  a:',
    '    image: a:1',
    '    network_mode: service:vpn',
    '  b:',
    '    image: b:1',
    '    network_mode: container:outside-this-file',
    '  c:',
    '    image: c:1',
    '    network_mode: service:${NS_OWNER}',
  ].join('\n');
  const { findings } = DS.lint(DS.parseCompose(yaml));
  assert.equal(findings.filter((f) => f.rule === 'network-mode-undefined-service').length, 0);
});

// --- undeclared-config + anonymous-volume (v0.40) ---------------------------

test('undeclared-config flags a service config missing from the top-level block', () => {
  const yml = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    configs:',
    '      - app_conf',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yml)).findings.filter((f) => f.rule === 'undeclared-config');
  assert.equal(found.length, 1);
  assert.equal(found[0].level, 'error');
  assert.equal(found[0].service, 'app');
  assert.match(found[0].message, /top-level `configs:` block/);
});

test('undeclared-config handles long-form entries (source:)', () => {
  const yml = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    configs:',
    '      - source: ghost_conf',
    '        target: /etc/nginx/nginx.conf',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yml)).findings.filter((f) => f.rule === 'undeclared-config');
  assert.equal(found.length, 1);
  assert.match(found[0].message, /ghost_conf/);
});

test('undeclared-config stays quiet when every config is declared, and on interpolation', () => {
  const declared = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    configs:',
    '      - app_conf',
    '      - ${EXTERNAL_CONF}',
    'configs:',
    '  app_conf:',
    '    file: ./nginx.conf',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(declared)).findings.some((f) => f.rule === 'undeclared-config'));

  const none = ['services:', '  app:', '    image: nginx:1.27'].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(none)).findings.some((f) => f.rule === 'undeclared-config'));
});

test('anonymous-volume flags both spellings — short form and long form without source', () => {
  const yml = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    volumes:',
    '      - /data',
    '      - type: volume',
    '        target: /cache',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yml)).findings.filter((f) => f.rule === 'anonymous-volume');
  assert.equal(found.length, 2);
  for (const f of found) assert.equal(f.level, 'warn');
  assert.match(found[0].message, /\/data/);
  assert.match(found[1].message, /\/cache/);
  // the trap in one line: redeploys keep the data, `down` + `up` loses it
  assert.match(found[0].message, /survives redeploys but not `down`/);
});

test('anonymous-volume spares named, bind and tmpfs mounts', () => {
  const yml = [
    'services:',
    '  app:',
    '    image: nginx:1.27',
    '    volumes:',
    '      - data:/data',
    '      - ./conf:/etc/nginx:ro',
    '      - type: tmpfs',
    '        target: /scratch',
    'volumes:',
    '  data:',
  ].join('\n');
  assert.ok(!DS.lint(DS.parseCompose(yml)).findings.some((f) => f.rule === 'anonymous-volume'));
});

test('completed-dependency-restarts: a one-shot wait on an always/unless-stopped dependency errors', () => {
  const yaml = [
    'services:',
    '  init:',
    '    image: alpine:3.20',
    '    restart: always',
    '  seed:',
    '    image: alpine:3.20',
    '    restart: unless-stopped',
    '  app:',
    '    image: alpine:3.20',
    '    depends_on:',
    '      init:',
    '        condition: service_completed_successfully',
    '      seed:',
    '        condition: service_completed_successfully',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'completed-dependency-restarts');
  assert.equal(found.length, 2);
  assert.ok(found.every((f) => f.service === 'app' && f.level === 'error'));
  assert.ok(found.some((f) => /`init` has `restart: always`/.test(f.message)));
  assert.ok(found.some((f) => /`seed` has `restart: unless-stopped`/.test(f.message)));
});

test('completed-dependency-restarts spares on-failure, "no", and absent restart', () => {
  const yaml = [
    'services:',
    '  retry:',
    '    image: alpine:3.20',
    '    restart: on-failure',
    '  oneshot:',
    '    image: alpine:3.20',
    '    restart: "no"',
    '  plain:',
    '    image: alpine:3.20',
    '  app:',
    '    image: alpine:3.20',
    '    depends_on:',
    '      retry:',
    '        condition: service_completed_successfully',
    '      oneshot:',
    '        condition: service_completed_successfully',
    '      plain:',
    '        condition: service_completed_successfully',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'completed-dependency-restarts');
  assert.equal(found.length, 0);
});

test('completed-dependency-restarts leaves other conditions and unknown targets alone', () => {
  const yaml = [
    'services:',
    '  db:',
    '    image: postgres:16',
    '    restart: always',
    '    healthcheck:',
    '      test: ["CMD", "pg_isready"]',
    '  app:',
    '    image: alpine:3.20',
    '    depends_on:',
    '      db:',
    '        condition: service_healthy',
    '      ghost:',
    '        condition: service_completed_successfully',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings;
  assert.equal(found.filter((f) => f.rule === 'completed-dependency-restarts').length, 0);
  // the dangling name still belongs to depends-on-unknown
  assert.ok(found.some((f) => f.rule === 'depends-on-unknown' && /ghost/.test(f.message)));
});

test('stop-signal-uncatchable: SIGKILL and its numeric string both warn, and name the reason', () => {
  const yaml = [
    'services:',
    '  db:',
    '    image: postgres:16',
    '    stop_signal: SIGKILL',
    '  q:',
    '    image: redis:7',
    '    stop_signal: "9"',
    '  frozen:',
    '    image: alpine:3.20',
    '    stop_signal: sigstop',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'stop-signal-uncatchable');
  assert.equal(found.length, 3);
  assert.ok(found.every((f) => f.level === 'warn'));
  assert.ok(found.some((f) => f.service === 'db' && /cannot be caught/.test(f.message)));
  assert.ok(found.some((f) => f.service === 'q'));
  assert.ok(found.some((f) => f.service === 'frozen' && /FREEZES/.test(f.message)));
});

test('stop-signal-uncatchable spares catchable signals, absence and interpolation', () => {
  const yaml = [
    'services:',
    '  a: { image: alpine:3.20, stop_signal: SIGTERM }',
    '  b: { image: alpine:3.20, stop_signal: SIGQUIT }',
    '  c: { image: alpine:3.20 }',
    '  d: { image: alpine:3.20, stop_signal: "${STOP_SIG}" }',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'stop-signal-uncatchable');
  assert.equal(found.length, 0);
});

test('secret-empty-when-unset: an unguarded ${VAR} secret warns, and a :? guard silences everything', () => {
  const yaml = [
    'services:',
    '  db:',
    '    image: postgres:16',
    '    environment:',
    '      POSTGRES_PASSWORD: ${DB_PASSWORD}',
    '  cache:',
    '    image: redis:7',
    '    environment:',
    '      REDIS_PASSWORD: ${REDIS_PASSWORD:?REDIS_PASSWORD is not set}',
  ].join('\n');
  const findings = DS.lint(DS.parseCompose(yaml)).findings;
  const unguarded = findings.filter((f) => f.rule === 'secret-empty-when-unset');
  assert.equal(unguarded.length, 1);
  assert.equal(unguarded[0].service, 'db');
  assert.equal(unguarded[0].level, 'warn');
  assert.ok(/empty string/.test(unguarded[0].message));
  // the guarded form must trip NOTHING — it used to false-positive as env-secret
  assert.ok(!findings.some((f) => f.service === 'cache' && (f.rule === 'env-secret' || f.rule === 'secret-empty-when-unset')));
});

test('secret-empty-when-unset: an empty default (${VAR:-}) is as unguarded as no modifier', () => {
  const yaml = [
    'services:',
    '  db:',
    '    image: postgres:16',
    '    environment:',
    '      - POSTGRES_PASSWORD=${DB_PASSWORD:-}',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'secret-empty-when-unset');
  assert.equal(found.length, 1);
  assert.equal(found[0].level, 'warn');
});

test('secret-empty-when-unset spares non-secret keys and compound values', () => {
  const yaml = [
    'services:',
    '  app:',
    '    image: alpine:3.20',
    '    environment:',
    '      LOG_LEVEL: ${LOG_LEVEL}',
    '      GREETING: hello-${NAME}',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'secret-empty-when-unset');
  assert.equal(found.length, 0);
});

test('env-secret: a literal default (${VAR:-hunter2}) is a committed secret, named without echoing it', () => {
  const yaml = [
    'services:',
    '  db:',
    '    image: postgres:16',
    '    environment:',
    '      POSTGRES_PASSWORD: ${DB_PASSWORD:-hunter2}',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'env-secret');
  assert.equal(found.length, 1);
  assert.equal(found[0].level, 'error');
  assert.ok(/falls back to a literal default/.test(found[0].message));
  assert.ok(!found[0].message.includes('hunter2'), 'the finding must never echo the secret');
});

test('build-arg-secret: the :? guard no longer false-positives, the literal default still fires', () => {
  const yaml = [
    'services:',
    '  api:',
    '    build:',
    '      context: .',
    '      args:',
    '        NPM_TOKEN: ${NPM_TOKEN:?NPM_TOKEN is required}',
    '  worker:',
    '    build:',
    '      context: .',
    '      args:',
    '        API_KEY: ${API_KEY:-sk-live-123}',
  ].join('\n');
  const found = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'build-arg-secret');
  assert.equal(found.length, 1);
  assert.equal(found[0].service, 'worker');
});

test('mem-reservation-exceeds-limit: a soft floor above the hard ceiling is an error (legacy pair)', () => {
  const yaml = [
    'services:',
    '  app:',
    '    image: postgres:17',
    '    mem_limit: 128m',
    '    mem_reservation: 256m',
  ].join('\n');
  const findings = DS.lint(DS.parseCompose(yaml)).findings;
  const hits = findings.filter((f) => f.rule === 'mem-reservation-exceeds-limit');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].level, 'error');
  assert.ok(/soft floor is above the hard ceiling/.test(hits[0].message));
});

test('mem-reservation-exceeds-limit: the deploy.resources form is judged too', () => {
  const yaml = [
    'services:',
    '  a:',
    '    image: nginx:1.27',
    '    deploy:',
    '      resources:',
    '        limits: { memory: 128M }',
    '        reservations: { memory: 200M }',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'mem-reservation-exceeds-limit');
  assert.equal(hits.length, 1);
});

test('mem-reservation-exceeds-limit: equal sizes are allowed (the daemon creates), different units compared right', () => {
  const yaml = [
    'services:',
    '  equal:',
    '    image: alpine:3.20',
    '    mem_limit: 128m',
    '    mem_reservation: 128m',
    '  underGig:',       // 512m reservation under a 1g limit: fine
    '    image: alpine:3.20',
    '    mem_limit: 1g',
    '    mem_reservation: 512m',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'mem-reservation-exceeds-limit');
  assert.equal(hits.length, 0);
});

test('mem-reservation-exceeds-limit: unit spellings (1gb > 512mb) still fire, and bytes compare', () => {
  const yaml = [
    'services:',
    '  a:',
    '    image: alpine:3.20',
    '    mem_limit: 536870912',  // 512Mi in bytes
    '    mem_reservation: 1gb',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'mem-reservation-exceeds-limit');
  assert.equal(hits.length, 1);
});

test('mem-reservation-exceeds-limit stays silent when either side is missing or an interpolation', () => {
  const yaml = [
    'services:',
    '  noLimit:',
    '    image: alpine:3.20',
    '    mem_reservation: 256m',
    '  interp:',
    '    image: alpine:3.20',
    '    mem_limit: ${MEM_MAX}',
    '    mem_reservation: 256m',
  ].join('\n');
  const hits = DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'mem-reservation-exceeds-limit');
  assert.equal(hits.length, 0);
});

test('parser normalizes memoryReservation from either spelling, null when absent', () => {
  const compose = [
    'services:',
    '  a:',
    '    image: nginx:1.27',
    '    deploy: { resources: { reservations: { memory: 256M } } }',
    '  b:',
    '    image: redis:7.4',
    '    mem_reservation: 134217728',
    '  c:',
    '    image: postgres:17',
  ].join('\n');
  const by = Object.fromEntries(DS.parseCompose(compose).services.map((s) => [s.name, s.memoryReservation]));
  assert.equal(by.a, '256M');
  assert.equal(by.b, '134217728');
  assert.equal(by.c, null);
});

// --- rule 57: ulimit-soft-exceeds-hard -------------------------------------
// Measured against a real daemon (29.x): `docker run --ulimit nofile=65536:1024`
// is refused on the spot ("ulimit soft limit must be less than or equal to
// hard limit"); the same pair in a compose file passes `docker compose config`
// silently and `up` dies at container create inside the runtime ("error
// setting rlimits for ready process: ... invalid argument"). Equal runs;
// -1 is unlimited and counts as larger than any finite value.

function lintUlimits(block) {
  const yaml = ['services:', '  app:', '    image: nginx:1.27', '    ulimits:', ...block.map((l) => `      ${l}`)].join('\n');
  return DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.rule === 'ulimit-soft-exceeds-hard');
}

test('ulimit-soft-exceeds-hard: a soft limit above the hard one is an error naming the resource', () => {
  const hits = lintUlimits(['nofile:', '  soft: 65536', '  hard: 1024']);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].level, 'error');
  assert.equal(hits[0].service, 'app');
  assert.match(hits[0].message, /ulimits\.nofile/);
  assert.match(hits[0].message, /65536/);
  assert.match(hits[0].message, /1024/);
  assert.match(hits[0].message, /refuses to start/);
});

test('ulimit-soft-exceeds-hard: equal, soft below hard and the single-number form are all fine', () => {
  assert.equal(lintUlimits(['nofile:', '  soft: 1024', '  hard: 1024']).length, 0, 'equal is allowed (measured: 1024:1024 runs)');
  assert.equal(lintUlimits(['nofile:', '  soft: 1024', '  hard: 65536']).length, 0, 'soft below hard');
  assert.equal(lintUlimits(['nofile: 20000', 'nproc: 4096']).length, 0, 'single number sets both — they cannot disagree');
});

test('ulimit-soft-exceeds-hard: -1 is unlimited — above any finite hard limit, but a hard -1 accepts anything', () => {
  const hits = lintUlimits(['nofile:', '  soft: -1', '  hard: 1024']);
  assert.equal(hits.length, 1, 'soft unlimited over a finite hard limit (measured: refused as "soft: -1 (unlimited), hard: 1024")');
  assert.match(hits[0].message, /-1 \(unlimited\)/);
  assert.equal(lintUlimits(['core:', '  soft: 0', '  hard: -1']).length, 0, 'finite soft under an unlimited hard');
  assert.equal(lintUlimits(['core:', '  soft: -1', '  hard: -1']).length, 0, 'both unlimited');
});

test('ulimit-soft-exceeds-hard: every offending resource gets its own finding; quoted integers are read', () => {
  const hits = lintUlimits(['nofile:', '  soft: 65536', '  hard: 1024', 'nproc:', '  soft: "8192"', '  hard: "4096"', 'core:', '  soft: 0', '  hard: 0']);
  assert.equal(hits.length, 2);
  // Findings come from the vm realm — compare by value, not by prototype.
  assert.deepEqual(JSON.parse(JSON.stringify(hits.map((h) => h.message.match(/ulimits\.(\w+)/)[1]).sort())), ['nofile', 'nproc']);
});

test('ulimit-soft-exceeds-hard: interpolated or unreadable values are never judged', () => {
  assert.equal(lintUlimits(['nofile:', '  soft: ${NOFILE_SOFT}', '  hard: 1024']).length, 0, 'interpolation on the soft side');
  assert.equal(lintUlimits(['nofile:', '  soft: 65536', '  hard: ${NOFILE_HARD}']).length, 0, 'interpolation on the hard side');
  assert.equal(lintUlimits(['nofile:', '  soft: many', '  hard: 1024']).length, 0, 'garbage');
  assert.equal(lintUlimits(['nofile: ${NOFILE}']).length, 0, 'interpolated single form');
});

// --- rule 58: zero-limit-is-unlimited --------------------------------------
// Measured against a real daemon (29.x, compose v5): every zero-valued limit
// passes `compose config` (which drops the key) and the container runs with
// the cgroup at `max` — pids.max at the parent's value, HostConfig.PidsLimit
// nil. The no-*-limit rules treated the zero as a cap; this one names it.

function lintZero(lines) {
  const yaml = ['services:', '  app:', '    image: nginx:1.27', ...lines.map((l) => `    ${l}`)].join('\n');
  return DS.lint(DS.parseCompose(yaml)).findings.filter((f) => f.service === 'app');
}
function zeroHits(lines) {
  return lintZero(lines).filter((f) => f.rule === 'zero-limit-is-unlimited');
}

test('zero-limit-is-unlimited: the legacy zeros fire once per resource, as warnings naming the absence', () => {
  const hits = zeroHits(['mem_limit: 0', 'pids_limit: 0', 'cpus: 0']);
  assert.equal(hits.length, 3);
  for (const h of hits) {
    assert.equal(h.level, 'warn');
    assert.match(h.message, /absence of one/);
    assert.match(h.message, /`max`/);
  }
  assert.ok(hits.some((h) => /mem_limit/.test(h.message)), 'memory');
  assert.ok(hits.some((h) => /pids_limit/.test(h.message)), 'pids');
  assert.ok(hits.some((h) => /`cpus`/.test(h.message)), 'cpu');
});

test('zero-limit-is-unlimited: deploy spellings, 0m and cpu_quota are zeros too', () => {
  const hits = zeroHits(['deploy:', '  resources:', '    limits:', '      pids: 0', '      memory: "0"', '      cpus: "0"']);
  assert.equal(hits.length, 3);
  assert.equal(zeroHits(['mem_limit: 0m']).length, 1, '0m is zero bytes');
  assert.equal(zeroHits(['mem_limit: "0g"']).length, 1, '0g is zero bytes');
  assert.equal(zeroHits(['cpu_quota: 0']).length, 1, 'cpu_quota 0');
});

test('zero-limit-is-unlimited: real caps, no caps and interpolations are never judged', () => {
  assert.equal(zeroHits(['mem_limit: 512m', 'pids_limit: 256', 'cpus: "0.50"']).length, 0, 'real caps');
  assert.equal(zeroHits(['cpus: 0.5']).length, 0, 'a fractional CPU is a cap');
  assert.equal(zeroHits([]).length, 0, 'no keys at all is the no-*-limit rules\' business');
  assert.equal(zeroHits(['mem_limit: ${MEM}', 'pids_limit: ${PIDS}']).length, 0, 'interpolations');
});

test('zero-limit-is-unlimited: exactly ONE finding per zeroed resource — the no-*-limit rules stand down', () => {
  const all = lintZero(['mem_limit: 0', 'pids_limit: 0', 'cpus: 0']);
  const limitRules = all.filter((f) => /^(no-memory-limit|no-pids-limit|no-cpu-limit|zero-limit-is-unlimited)$/.test(f.rule));
  assert.equal(limitRules.length, 3);
  assert.ok(limitRules.every((f) => f.rule === 'zero-limit-is-unlimited'));
  // ...and with the key absent the classic rules are still the ones talking.
  const none = lintZero([]).filter((f) => /^(no-memory-limit|no-pids-limit|no-cpu-limit)$/.test(f.rule));
  assert.equal(none.length, 3);
});
