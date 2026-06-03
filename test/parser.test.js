'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { loadDockerScope, sample, sampleFileMap } = require('./helper');

const DS = loadDockerScope();
const names = (m) => [...m.services].map((s) => s.name).sort();

test('parseCompose builds the service model for a single file', () => {
  const m = DS.parseCompose(sample('example.yml'));
  assert.deepEqual(names(m), ['api', 'cache', 'db', 'web', 'worker']);

  const web = m.services.find((s) => s.name === 'web');
  assert.equal(web.image, 'nginx:1.27');
  assert.deepEqual([...web.depends_on], ['api']);
  assert.ok(web.ports.some((p) => p.published === 80 && p.target === 80 && p.protocol === 'tcp'));

  assert.deepEqual([...m.networks].sort(), ['backend', 'frontend']);
  assert.deepEqual([...m.namedVolumes], ['db-data']);
});

test('parseCompose merges include: files via the fileMap', () => {
  const m = DS.parseCompose(sample('include-main.yml'), sampleFileMap());
  assert.deepEqual(names(m), ['api', 'db', 'logger', 'metrics', 'proxy']);
  assert.deepEqual([...m.warnings], []);
});

test('parseCompose resolves an extends: chain, inheriting base fields', () => {
  const m = DS.parseCompose(sample('extends-main.yml'), sampleFileMap());
  const api = m.services.find((s) => s.name === 'api');
  assert.equal(api.restart, 'unless-stopped'); // inherited from app-base
  assert.ok(api.healthcheck); // inherited from app-base
  assert.equal(api.image, 'node:20-alpine'); // own value overrides the base
});

test('parseCompose attaches detected stack info from build manifests', () => {
  const m = DS.parseCompose(sample('stack-main.yml'), sampleFileMap());
  const api = m.services.find((s) => s.name === 'api');
  assert.ok(api.stack, 'api should carry a detected stack');
  assert.equal(api.stack.language, 'Node');
  assert.equal(api.stack.framework, 'Express');
});

test('parseCompose normalizes object-form depends_on and networks to arrays', () => {
  const yaml = [
    'services:',
    '  web:',
    '    image: nginx:1',
    '    depends_on:',
    '      api:',
    '        condition: service_healthy',
    '    networks:',
    '      frontend: {}',
    'networks:',
    '  frontend: {}',
  ].join('\n');
  const web = DS.parseCompose(yaml).services[0];
  assert.deepEqual([...web.depends_on], ['api']);
  assert.deepEqual([...web.networks], ['frontend']);
});

test('include: collisions resolve in favour of the including (main) file', () => {
  const fileMap = new Map([
    ['inc.yml', 'services:\n  api:\n    image: included:1\n  extra:\n    image: extra:1\n'],
  ]);
  const main = 'include:\n  - inc.yml\nservices:\n  api:\n    image: main:1\n';
  const m = DS.parseCompose(main, fileMap);
  assert.equal(m.services.find((s) => s.name === 'api').image, 'main:1');
  assert.deepEqual([...m.services].map((s) => s.name).sort(), ['api', 'extra']);
});

test('extends concatenates array fields and lets the child override scalars', () => {
  const fileMap = new Map([
    ['base.yml', 'services:\n  b:\n    image: base:1\n    ports: ["9000:9000"]\n'],
  ]);
  const main = 'services:\n  web:\n    extends:\n      file: base.yml\n      service: b\n    image: web:1\n    ports: ["8080:80"]\n';
  const web = DS.parseCompose(main, fileMap).services[0];
  assert.equal(web.image, 'web:1'); // child scalar wins
  assert.deepEqual([...web.ports].map((p) => p.published), [9000, 8080]); // arrays concat, base first
});

test('parseCompose throws a clear error on invalid YAML', () => {
  let err;
  try {
    DS.parseCompose('services:\n  web:\n   image: x\n    bad: indent');
  } catch (e) {
    err = e;
  }
  assert.ok(err, 'should have thrown');
  assert.match(err.message, /YAML parse error/);
});

test('parseCompose rejects an empty or non-object document', () => {
  let err;
  try {
    DS.parseCompose('42');
  } catch (e) {
    err = e;
  }
  assert.ok(err, 'should have thrown');
  assert.match(err.message, /Empty or invalid/);
});
