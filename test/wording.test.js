// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const DENIAL = /no evidential weight|carr(y|ies) no evidential|test network receipts/i;

function sources(dir) {
  const out = [];
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name);
    if (fs.statSync(p).isDirectory()) out.push(...sources(p));
    else if (/\.(js|ts|md)$/.test(name)) out.push(p);
  }
  return out;
}

test('the readme, the library and the command line describe the evidence of a receipt the same way', () => {
  const files = [path.join(ROOT, 'README.md'), path.join(ROOT, 'index.d.ts')].concat(sources(path.join(ROOT, 'lib')), sources(path.join(ROOT, 'bin')));
  for (const f of files) assert.doesNotMatch(fs.readFileSync(f, 'utf8'), DENIAL, path.relative(ROOT, f));
  const help = spawnSync(process.execPath, [path.join(ROOT, 'bin', 'qstamp.js'), 'help'], { encoding: 'utf8' });
  assert.doesNotMatch(help.stdout + help.stderr, DENIAL);
});
