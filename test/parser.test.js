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

test('parseCompose keeps the long-form depends_on condition, null for the short form', () => {
  const yaml = [
    'services:',
    '  web:',
    '    image: nginx:1',
    '    depends_on:',
    '      api:',
    '        condition: service_healthy',
    '      queue: {}',
    '  worker:',
    '    image: node:22',
    '    depends_on:',
    '      - api',
    '  api:',
    '    image: node:22',
    '  queue:',
    '    image: redis:7',
  ].join('\n');
  const { services } = DS.parseCompose(yaml);
  const web = services.find((s) => s.name === 'web');
  const worker = services.find((s) => s.name === 'worker');
  assert.equal(web.dependsOnConditions.api, 'service_healthy');
  assert.equal(web.dependsOnConditions.queue, null, 'empty long-form entry → no condition');
  assert.equal(worker.dependsOnConditions.api, null, 'short form → no condition');
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

test('parseCompose normalizes tmpfs to target paths: string or list, options stripped', () => {
  const yaml = [
    'services:',
    '  one:',
    '    image: alpine:3.20',
    '    tmpfs: /run',
    '  many:',
    '    image: alpine:3.20',
    '    tmpfs:',
    '      - /run',
    '      - /tmp/cache:size=64m,mode=1777',
    '  none:',
    '    image: alpine:3.20',
  ].join('\n');
  const model = DS.parseCompose(yaml);
  const byName = Object.fromEntries(model.services.map((s) => [s.name, s]));
  // vm-realm arrays fail deepEqual on prototype — compare via JSON.
  assert.equal(JSON.stringify(byName.one.tmpfs), '["/run"]');
  assert.equal(JSON.stringify(byName.many.tmpfs), '["/run","/tmp/cache"]');
  assert.equal(JSON.stringify(byName.none.tmpfs), '[]');
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

test('parseCompose exposes profiles (list, bare string, absent)', () => {
  const yml = [
    'services:',
    '  a:',
    '    image: redis:7',
    '    profiles: [extra, other]',
    '  b:',
    '    image: redis:7',
    '    profiles: solo',
    '  c:',
    '    image: redis:7',
  ].join('\n');
  const model = DS.parseCompose(yml);
  const byName = Object.fromEntries(model.services.map((s) => [s.name, s]));
  assert.equal(JSON.stringify(byName.a.profiles), JSON.stringify(['extra', 'other']));
  assert.equal(JSON.stringify(byName.b.profiles), JSON.stringify(['solo']));
  assert.equal(JSON.stringify(byName.c.profiles), JSON.stringify([]));
});

test('parseCompose exposes sysctls (map and list form) and utsMode', () => {
  const yml = [
    'services:',
    '  a:',
    '    image: redis:7',
    '    uts: host',
    '    sysctls:',
    '      net.core.somaxconn: 1024',
    '  b:',
    '    image: redis:7',
    '    sysctls:',
    '      - vm.max_map_count=262144',
    '  c:',
    '    image: redis:7',
  ].join('\n');
  const model = DS.parseCompose(yml);
  const byName = Object.fromEntries(model.services.map((s) => [s.name, s]));
  assert.equal(JSON.stringify(byName.a.sysctls), JSON.stringify([{ key: 'net.core.somaxconn', value: '1024' }]));
  assert.equal(byName.a.utsMode, 'host');
  assert.equal(JSON.stringify(byName.b.sysctls), JSON.stringify([{ key: 'vm.max_map_count', value: '262144' }]));
  assert.equal(byName.b.utsMode, null);
  assert.equal(JSON.stringify(byName.c.sysctls), JSON.stringify([]));
});
