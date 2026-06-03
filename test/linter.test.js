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
