// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const pkg = require('../package.json');
const wire = require('../lib/wire');

const DIR = path.join(__dirname, '..', 'contract');

function expected() {
  const line = fs.readFileSync(path.join(DIR, 'QStamp.qbc.sha256'), 'utf8').trim();
  const m = /^([0-9a-f]{64}) {2}QStamp\.qbc$/.exec(line);
  assert.ok(m, 'contract/QStamp.qbc.sha256 holds one hash line');
  return m[1];
}

test('the shipped container matches its recorded hash', () => {
  const bytes = fs.readFileSync(path.join(DIR, 'QStamp.qbc'));
  assert.ok(bytes.length > 0);
  assert.strictEqual(bytes.subarray(0, 4).toString('ascii'), 'QVM1');
  assert.strictEqual(crypto.createHash('sha256').update(bytes).digest('hex'), expected());
});

test('the container, its hash and its build script are published with the package', () => {
  assert.ok(pkg.files.includes('contract/'));
  assert.ok(pkg.files.includes('scripts/build-contract.sh'));
  const script = fs.readFileSync(path.join(__dirname, '..', 'scripts', 'build-contract.sh'), 'utf8');
  assert.match(script, /QUANTA_COMMIT="071324a83f49aba0c638b61446f87b661a1008b1"/);
  for (const f of ['QStamp.interface.json', 'templates/QStampIssuer.interface.json', 'templates/QStampCouncil.interface.json']) {
    assert.ok(fs.existsSync(path.join(DIR, f)), f);
  }
});

test('argument offsets come from the interface the compiler emitted for each entry', () => {
  const doc = JSON.parse(fs.readFileSync(path.join(DIR, 'QStamp.interface.json'), 'utf8'));
  const entries = Object.fromEntries(doc.contracts[0].entries.map((e) => [e.name, Object.fromEntries(e.args.map((a) => [a.key, a.offset]))]));
  assert.deepStrictEqual(wire.LAYOUTS.stamp.at, { hi: entries.stamp.hi, lo: entries.stamp.lo, kind: entries.stamp.kind });
  assert.deepStrictEqual(wire.LAYOUTS.stampUntil.at, { hi: 120, lo: 136, kind: 152, until: 160 });
  assert.deepStrictEqual(wire.LAYOUTS.stamp.at, { hi: 120, lo: 136, kind: 152 });
  assert.deepStrictEqual(wire.LAYOUTS.issuerStamp.at, { commitment: 120 });
  assert.deepStrictEqual(wire.LAYOUTS.councilStamp.at, { hi: 168, lo: 184 });
  assert.strictEqual(wire.HOST_CONTEXT_BYTES, 120);
  assert.deepStrictEqual(
    [wire.STAMP_SELECTOR, wire.STAMP_UNTIL_SELECTOR, wire.STAMPED_SELECTOR, wire.STAMPED_UNTIL_SELECTOR, wire.COMMITMENT_STAMPED_SELECTOR, wire.LAYOUTS.issuerStamp.selector, wire.LAYOUTS.councilStamp.selector],
    ['6ae4cf77', 'c1c5ac38', '5a110849', '16676021', '14369772', '1effe529', 'd002a3d1'],
  );
});

test('stamp arguments are encoded at the emitted offsets and recognised only there', () => {
  const anchored = crypto.randomBytes(32);
  const args = Buffer.from(wire.stampArgs(anchored, '6', 1800000000), 'hex');
  assert.strictEqual(args.subarray(0, 4).toString('hex'), wire.STAMP_UNTIL_SELECTOR);
  assert.strictEqual(args.length, 4 + 168);
  assert.ok(args.subarray(4, 124).equals(Buffer.alloc(120)));
  assert.ok(args.subarray(124, 140).equals(anchored.subarray(0, 16)));
  assert.ok(args.subarray(140, 156).equals(anchored.subarray(16)));
  assert.strictEqual(args.readBigUInt64BE(156), 6n);
  assert.strictEqual(args.readBigUInt64BE(164), 1800000000n);
  const wrapped = Buffer.concat([crypto.randomBytes(40), args, crypto.randomBytes(40)]);
  assert.ok(wire.callMatches(wrapped, anchored, '6', 1800000000));
  assert.ok(!wire.callMatches(wrapped, anchored, '6', 1800000001));
  assert.ok(!wire.callMatches(wrapped, anchored, '7', 1800000000));
  const earlier = Buffer.concat([args.subarray(0, 124), args.subarray(164, 172), args.subarray(124, 164)]);
  assert.ok(!wire.callMatches(earlier, anchored, '6', 1800000000));
  const plain = Buffer.from(wire.stampArgs(anchored, '6'), 'hex');
  assert.strictEqual(plain.subarray(0, 4).toString('hex'), wire.STAMP_SELECTOR);
  assert.strictEqual(plain.length, 4 + 160);
  assert.ok(wire.callMatches(plain, anchored, '6'));
});

test('a custom contract call carries the commitment at the offsets of a known template', () => {
  const anchored = crypto.randomBytes(32);
  const issuer = Buffer.alloc(4 + wire.LAYOUTS.issuerStamp.size);
  Buffer.from(wire.LAYOUTS.issuerStamp.selector, 'hex').copy(issuer, 0);
  anchored.copy(issuer, 4 + 120);
  assert.ok(wire.carriesCommitment(issuer, anchored));
  const misplaced = Buffer.alloc(issuer.length);
  issuer.copy(misplaced, 0, 0, 4);
  anchored.copy(misplaced, 4 + 160);
  assert.ok(!wire.carriesCommitment(misplaced, anchored));
  const council = Buffer.alloc(4 + wire.LAYOUTS.councilStamp.size);
  Buffer.from(wire.LAYOUTS.councilStamp.selector, 'hex').copy(council, 0);
  anchored.copy(council, 4 + 168);
  assert.ok(wire.carriesCommitment(council, anchored));
  const other = Buffer.concat([Buffer.from('0badc0de', 'hex'), Buffer.alloc(150), anchored]);
  assert.ok(wire.carriesCommitment(other, anchored));
  assert.ok(!wire.carriesCommitment(other, crypto.randomBytes(32)));
});

test('the container rebuilds from source when a compiler is given', { skip: !process.env.QUANTA_CLI }, () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'qstamp-contract-'));
  try {
    fs.copyFileSync(path.join(DIR, 'QStamp.qs'), path.join(work, 'QStamp.qs'));
    const env = Object.assign({}, process.env);
    delete env.QUANTA_PROVENANCE_KEY_FILE;
    execFileSync(process.env.QUANTA_CLI, ['build', 'QStamp.qs'], { cwd: work, env, stdio: 'ignore' });
    const rebuilt = fs.readFileSync(path.join(work, 'QStamp.qbc'));
    assert.strictEqual(crypto.createHash('sha256').update(rebuilt).digest('hex'), expected());
    const emitted = JSON.parse(execFileSync(process.env.QUANTA_CLI, ['emit', 'QStamp.qs'], { cwd: work, env }).toString('utf8'));
    assert.ok(Buffer.from(emitted.contracts[0].container, 'hex').equals(rebuilt));
    delete emitted.contracts[0].container;
    assert.deepStrictEqual(emitted, JSON.parse(fs.readFileSync(path.join(DIR, 'QStamp.interface.json'), 'utf8')));
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
});
