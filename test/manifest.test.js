'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { loadDockerScope, sample } = require('./helper');

const DS = loadDockerScope();

test('parseManifest detects Node / Express from a package.json', () => {
  const pm = DS.parseManifest('package.json', sample('api.package.json'));
  assert.equal(pm.language, 'Node');
  assert.equal(pm.framework, 'Express');
  assert.ok([...pm.dbClients].some((c) => /PostgreSQL/.test(c)), 'detects a Postgres client');
  assert.equal(typeof pm.depCount, 'number');
});

test('parseManifest detects Python / FastAPI from a requirements.txt', () => {
  const pm = DS.parseManifest('requirements.txt', sample('worker.requirements.txt'));
  assert.equal(pm.language, 'Python');
  assert.equal(pm.framework, 'FastAPI');
  assert.ok([...pm.queueClients].some((c) => /Celery/.test(c)), 'detects Celery');
});
