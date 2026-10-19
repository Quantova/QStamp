// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const q = require('..');

const NETWORKED = new Set(['anchor', 'complete', 'stamp', 'chainTime', 'consume', 'authorise', 'act', 'recordDomain', 'folderLedger', 'fileLedger', 'digestFile', 'executedIn', 'ledgerActions', 'ledgerLatest']);
const SEEDS = [undefined, null, 0, -1, NaN, 1e308, '', 'x', true, 10n, [], {}, () => 1, Object.create(null), new Uint8Array(3), new Date(NaN)];
const KEYS = ['__proto__', 'constructor', 'prototype', 'type', 'statement', 'signature', 'signer', 'anchor', 'format', 'record', 'chain', 'proof', 'digest', 'salt', 'path', 'index', 'size', 'time', 'key', 'toString'];

function rng(seed) {
  let s = seed >>> 0;
  return (n) => {
    s = (Math.imul(s, 1103515245) + 12345) >>> 0;
    return s % n;
  };
}

function value(r, depth) {
  const k = r(9);
  if (depth > 5 || k < 3) return SEEDS[r(SEEDS.length)];
  if (k < 5) return Array.from({ length: r(4) }, () => value(r, depth + 1));
  const o = {};
  for (let i = r(6); i > 0; i -= 1) o[KEYS[r(KEYS.length)]] = value(r, depth + 1);
  return r(3) === 0 ? JSON.parse(JSON.stringify(o, (key, v) => (typeof v === 'bigint' || typeof v === 'function' ? String(v) : v)).replace('"type"', '"__proto__"')) : o;
}

test('hostile input to every offline function is refused in a controlled way and never pollutes Object.prototype', async () => {
  const r = rng(0x51ed);
  const fns = Object.keys(q).filter((k) => typeof q[k] === 'function' && !NETWORKED.has(k) && k !== 'generateKey' && k !== 'deploymentDomain');
  const at = new Date().toISOString();
  for (let i = 0; i < 600; i += 1) {
    const fn = fns[r(fns.length)];
    const input = value(r, 0);
    const opts = fn === 'verify' ? Object.assign({ at, requireAnchor: false }, r(2) ? { type: 'x' } : {}) : value(r, 0);
    try {
      const out = await q[fn](input, opts);
      if (fn === 'verify') assert.notStrictEqual(out && out.valid, true, 'hostile input verified valid');
    } catch (e) {
      assert.ok(e instanceof Error, fn + ' threw a non error');
      assert.ok(!(e instanceof TypeError || e instanceof RangeError || e instanceof ReferenceError), fn + ' escaped with ' + e.constructor.name + ' ' + e.message);
    }
    assert.strictEqual(Object.prototype.type, undefined);
    assert.strictEqual(Object.prototype.statement, undefined);
  }
});
