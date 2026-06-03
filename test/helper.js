'use strict';

// Test harness for the browser modules without a browser or a bundler.
//
// Each file in src/ hangs its public API off `window.DockerScope`. We load the
// pure-logic modules into a single vm sandbox whose global doubles as `window`,
// and provide the one CDN global the parser needs (`jsyaml`, the same js-yaml
// 4.1.0 the page pulls from jsDelivr). The DOM/Cytoscape modules (app.js,
// graph.js) are skipped — they need a real DOM and carry no parsing logic.
//
// NB: values returned from the sandbox carry the sandbox's prototypes, so
// assert.deepStrictEqual against main-realm literals fails on arrays/objects.
// Spread sandbox arrays ([...arr]) before deep-comparing, or assert on
// primitives / membership.

const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const jsyaml = require('js-yaml');

const ROOT = path.join(__dirname, '..');
const SRC = path.join(ROOT, 'src');
const SAMPLES = path.join(ROOT, 'samples');

// Dependency order: dockerfile + manifest parsers before the compose parser
// that calls them, linter last.
const MODULES = ['dockerfile.js', 'manifest.js', 'parser.js', 'linter.js'];

function loadDockerScope() {
  const sandbox = { console, jsyaml };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  for (const rel of MODULES) {
    vm.runInContext(fs.readFileSync(path.join(SRC, rel), 'utf8'), sandbox, { filename: rel });
  }
  return sandbox.DockerScope;
}

function sample(name) {
  return fs.readFileSync(path.join(SAMPLES, name), 'utf8');
}

// Map<basename, content> over every fixture, the way the app builds it from
// uploaded files — used to resolve include: / extends: and build manifests.
function sampleFileMap() {
  const map = new Map();
  for (const name of fs.readdirSync(SAMPLES)) {
    map.set(name, fs.readFileSync(path.join(SAMPLES, name), 'utf8'));
  }
  return map;
}

module.exports = { loadDockerScope, sample, sampleFileMap };
