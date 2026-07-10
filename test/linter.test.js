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
