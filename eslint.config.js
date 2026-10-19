const js = require('@eslint/js');
const security = require('eslint-plugin-security');
const globals = require('globals');
module.exports = [
  { ignores: ['wasm/**', 'native/**', 'node_modules/**', 'pkg/**', 'contract/**', 'coverage/**'] },
  js.configs.recommended,
  security.configs.recommended,
  { languageOptions: { ecmaVersion: 2024, sourceType: 'commonjs', globals: { ...globals.node } } },
  { files: ['**/*.mjs'], languageOptions: { sourceType: 'module' } },
  {
    rules: {
      'no-unused-vars': ['error', { caughtErrors: 'none' }],
      'no-control-regex': 'off',
      'no-misleading-character-class': 'off',
      'security/detect-object-injection': 'off',
      'security/detect-non-literal-fs-filename': 'off',
    },
  },
];
