'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { loadDockerScope } = require('./helper');

const DS = loadDockerScope();

test('parseCompose classifies named, bind and anonymous volumes', () => {
  const yaml = [
    'services:',
    '  db:',
    '    image: postgres:16',
    '    volumes:',
    '      - db-data:/var/lib/postgresql/data',
    '      - ./init.sql:/docker-entrypoint-initdb.d/init.sql:ro',
    '      - /tmp/cache',
    'volumes:',
    '  db-data:',
  ].join('\n');
  const vols = DS.parseCompose(yaml).services[0].volumes;

  assert.equal(vols[0].type, 'named');
  assert.equal(vols[0].source, 'db-data');
  assert.equal(vols[1].type, 'bind');
  assert.equal(vols[1].readonly, true);
  assert.equal(vols[2].type, 'anonymous');
  assert.equal(vols[2].target, '/tmp/cache');
});

test('parseCompose surfaces named volumes at the top level', () => {
  const yaml = [
    'services:',
    '  db:',
    '    image: postgres:16',
    '    volumes:',
    '      - db-data:/var/lib/postgresql/data',
    'volumes:',
    '  db-data:',
  ].join('\n');
  assert.deepEqual([...DS.parseCompose(yaml).namedVolumes], ['db-data']);
});

test('parseCompose parses short-form port variants (host IP, protocol)', () => {
  const yaml = [
    'services:',
    '  a:',
    '    image: nginx:1',
    '    ports:',
    '      - "127.0.0.1:8080:80"',
    '      - "53:53/udp"',
  ].join('\n');
  const [a] = DS.parseCompose(yaml).services;

  assert.equal(a.ports[0].host_ip, '127.0.0.1');
  assert.equal(a.ports[0].published, 8080);
  assert.equal(a.ports[0].target, 80);
  assert.equal(a.ports[1].protocol, 'udp');
});
