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
