'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { loadDockerScope, sample } = require('./helper');

const DS = loadDockerScope();

test('parseDockerfile parses a multi-stage Dockerfile', () => {
  const df = DS.parseDockerfile(sample('api.Dockerfile'));
  assert.equal(df.multiStage, true);
  assert.ok(df.stages.length >= 2);

  const stageNames = [...df.stages].map((s) => s.name);
  assert.ok(stageNames.includes('builder'), 'has a builder stage');
  assert.ok(stageNames.includes('runner'), 'has a runner stage');

  assert.ok(df.finalStage, 'exposes a final stage');
  assert.ok([...df.finalStage.expose].includes('3000'), 'final stage EXPOSEs 3000');
});

test('parseDockerfile marks a single-stage Dockerfile as not multi-stage', () => {
  const df = DS.parseDockerfile(sample('worker.Dockerfile'));
  assert.equal(df.multiStage, false);
  assert.equal(df.stages.length, 1);
});

test('languageVersionFromDockerfile reads the version from the base image tag', () => {
  const df = DS.parseDockerfile(sample('api.Dockerfile'));
  assert.equal(DS.languageVersionFromDockerfile(df, 'Node'), '20');
});
