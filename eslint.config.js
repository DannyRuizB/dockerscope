const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
  js.configs.recommended,
  {
    files: ['src/**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'script',
      globals: {
        ...globals.browser,
        // Loaded from CDN <script> tags in index.html, not bundled.
        jsyaml: 'readonly',
        cytoscape: 'readonly',
        layoutBase: 'readonly',
        coseBase: 'readonly',
        cytoscapeFcose: 'readonly',
        cytoscapeSvg: 'readonly',
        cytoscapeGridGuide: 'readonly',
      },
    },
    rules: {
      // Allow intentional throwaway bindings named _ (e.g. catch (_) {}).
      'no-unused-vars': ['error', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
        caughtErrors: 'all',
        caughtErrorsIgnorePattern: '^_',
      }],
    },
  },
  {
    // Node-based test suite (node:test + vm), run outside the browser.
    files: ['test/**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'commonjs',
      globals: { ...globals.node },
    },
  },
];
