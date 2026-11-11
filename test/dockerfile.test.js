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

// HEALTHCHECK: measured (compose v5.3.1) - the stage's own check runs (healthy),
// the last one wins (`HEALTHCHECK NONE` after one = none), a `FROM base AS app`
// inherits base's check, a FROM an outside image after such a stage does not.
test('parseDockerfile reads HEALTHCHECK, NONE, the last one winning and stage inheritance', () => {
  const own = DS.parseDockerfile('FROM busybox\nHEALTHCHECK --interval=2s CMD true\nCMD ["sleep","300"]\n');
  assert.equal(own.healthcheck.none, false);
  assert.equal(own.healthcheck.raw, '--interval=2s CMD true');
  const off = DS.parseDockerfile('FROM busybox\nHEALTHCHECK CMD true\nHEALTHCHECK NONE\n');
  assert.equal(off.healthcheck.none, true);
  const inherited = DS.parseDockerfile('FROM busybox AS base\nHEALTHCHECK CMD true\nFROM BASE AS app\nCMD ["sleep","300"]\n');
  assert.equal(inherited.healthcheck.none, false, 'stage names are case-insensitive');
  const fresh = DS.parseDockerfile('FROM busybox AS base\nHEALTHCHECK CMD true\nFROM busybox AS app\n');
  assert.equal(fresh.healthcheck, null);
  assert.equal(DS.parseDockerfile('FROM busybox\nCMD ["true"]\n').healthcheck, null);
});
