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
    '    healthcheck:',
    '      test: ["CMD", "true"]',
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

test('the insecure sample trips every security rule at once', () => {
  const rules = new Set(DS.lint(DS.parseCompose(sample('insecure.yml'))).findings.map((f) => f.rule));
  for (const r of [
    'image-latest', 'docker-socket-mount', 'privileged', 'host-namespace',
    'dangerous-cap', 'sensitive-host-mount', 'no-new-privileges',
    'env-secret', 'port-public', 'security-unconfined', 'build-arg-secret',
    'port-conflict',
  ]) {
    assert.ok(rules.has(r), `expected rule '${r}'`);
  }
});
