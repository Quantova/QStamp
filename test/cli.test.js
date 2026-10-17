// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile, spawnSync } = require('child_process');
const qstamp = require('..');
const { makeChain, client, gateway, SEED } = require('./chain');

const BIN = path.join(__dirname, '..', 'bin', 'qstamp.js');

function run(args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [BIN, ...args], { timeout: 60000 }, (err, stdout, stderr) => {
      resolve({ code: err ? err.code : 0, stdout, stderr });
    });
  });
}

test('the command line marks a receipt confirmed only by chosen endpoints as unproven with its own exit status', async (t) => {
  const chain = makeChain();
  const record = Buffer.from('a cli record');
  const [receipt] = await qstamp.stamp({
    seed: SEED,
    index: 0,
    records: [{ digest: qstamp.digestBytes(record) }],
    clients: [client(chain, 'https://alpha.example'), client(chain, 'https://beta.example')],
    timeoutMs: 1000,
  });
  const gw = await gateway(chain);
  t.after(() => gw.close());
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qstamp-cli-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'r.qstamp.json');
  fs.writeFileSync(file, JSON.stringify(receipt));
  const digest = qstamp.digestBytes(record).toString('hex');

  const unproven = await run(['verify', file, '--digest', digest, '--rpc', gw.url, '--trust-custom-endpoints', '--allow-loopback']);
  assert.strictEqual(unproven.code, 3, unproven.stdout + unproven.stderr);
  assert.match(unproven.stdout, /WARNING {2}this receipt is NOT proven/);
  assert.match(unproven.stdout, /^UNPROVEN/m);
  assert.doesNotMatch(unproven.stdout, /^VALID/m);
  assert.match(unproven.stdout, /trust custom-endpoints/);

  const refused = await run(['verify', file, '--digest', digest, '--rpc', gw.url, '--allow-loopback']);
  assert.strictEqual(refused.code, 2);
  assert.match(refused.stdout, /trustCustomEndpoints/);

  const loopback = await run(['verify', file, '--digest', digest, '--rpc', gw.url, '--trust-custom-endpoints']);
  assert.strictEqual(loopback.code, 2);
  assert.match(loopback.stdout, /loopback/);

  const wrong = await run(['verify', file, '--digest', '00'.repeat(32), '--rpc', gw.url, '--trust-custom-endpoints', '--allow-loopback']);
  assert.strictEqual(wrong.code, 1);
  assert.match(wrong.stdout, /^INVALID/m);

  const json = await run(['verify', file, '--digest', digest, '--rpc', gw.url, '--trust-custom-endpoints', '--allow-loopback', '--json']);
  const parsed = JSON.parse(json.stdout);
  assert.strictEqual(parsed.status, 'unproven');
  assert.strictEqual(parsed.valid, false);
  assert.strictEqual(parsed.trust, 'custom-endpoints');
});

test('the command line refuses an option it does not know', async () => {
  const r = await run(['verify', 'x.json', '--trust-everything']);
  assert.strictEqual(r.code, 64);
});

test('devices, pipes, links and missing files are refused at once with the input error status', { skip: process.platform === 'win32' }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qstamp-cli-io-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const chain = makeChain();
  const [receipt] = await qstamp.stamp({
    seed: SEED,
    index: 0,
    records: [{ digest: qstamp.digestBytes(Buffer.from('x')) }],
    clients: [client(chain, 'https://alpha.example'), client(chain, 'https://beta.example')],
    timeoutMs: 1000,
  });
  const file = path.join(dir, 'r.qstamp.json');
  fs.writeFileSync(file, JSON.stringify(receipt));
  const fifo = path.join(dir, 'pipe');
  const made = spawnSync('mkfifo', [fifo]);
  const link = path.join(dir, 'link');
  fs.symlinkSync(file, link);
  const quick = (args) => new Promise((resolve) => {
    execFile(process.execPath, [BIN, ...args], { timeout: 15000 }, (err, stdout, stderr) => {
      resolve({ code: err ? err.code : 0, signal: err ? err.signal : null, stdout, stderr });
    });
  });
  const cases = [
    ['hash', '/dev/zero'],
    ['verify', file, '--file', '/dev/zero'],
    ['verify', path.join(dir, 'missing.qstamp.json'), '--digest', '00'.repeat(32)],
    ['verify', '/dev/zero', '--digest', '00'.repeat(32)],
    ['hash', link],
    ['verify', link, '--digest', '00'.repeat(32)],
  ];
  if (made.status === 0) {
    cases.push(['hash', fifo], ['verify', file, '--file', fifo], ['verify', fifo, '--digest', '00'.repeat(32)], ['complete', fifo]);
  }
  for (const args of cases) {
    const started = Date.now();
    const r = await quick(args);
    assert.strictEqual(r.signal, null, args.join(' ') + ' was still running');
    assert.strictEqual(r.code, 64, args.join(' ') + ' ' + r.stderr);
    assert.ok(Date.now() - started < 10000);
    assert.doesNotMatch(r.stdout, /VALID|INVALID/);
  }
  await assert.rejects(qstamp.digestFile('/dev/zero'), /not a regular file/);
  await assert.rejects(qstamp.digestFile(link), /symbolic link/);
  assert.deepStrictEqual(await qstamp.digestFile(file), qstamp.digestBytes(fs.readFileSync(file)));
  const dup = path.join(dir, 'dup.qstamp.json');
  fs.writeFileSync(dup, JSON.stringify(receipt).replace('{', '{"root":"00",'));
  assert.strictEqual((await quick(['verify', dup, '--digest', '00'.repeat(32)])).code, 1);
});
