// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const qstamp = require('..');
const D = require('../lib/domain');

const contract = qstamp.NETWORKS.testnet.contract;
const genesis = qstamp.NETWORKS.testnet.genesis;
const later = 'ab'.repeat(32);

function place(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qstamp-ledger-'));
  t.after(() => {
    if (process.platform === 'darwin') {
      try { execFileSync('/bin/chmod', ['-RN', dir], { stdio: 'ignore' }); } catch (e) { void e; }
    }
    fs.chmodSync(dir, 0o700);
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return dir;
}

test('a linked domain ledger is refused when read or recorded', (t) => {
  const dir = place(t);
  const real = path.join(dir, 'real.json');
  D.recordDomain(real, { contract, genesis });
  const link = path.join(dir, 'link.json');
  fs.symlinkSync(real, link);
  assert.throws(() => D.readLedger(link), /symbolic link/);
  assert.throws(() => D.recordDomain(link, { contract, genesis: later }), /symbolic link/);
  assert.strictEqual(D.readLedger(real).deployments.length, 1);
});

test('a domain ledger others can write is refused', (t) => {
  const dir = place(t);
  const file = path.join(dir, 'domains.json');
  D.recordDomain(file, { contract, genesis });
  for (const mode of [0o666, 0o620, 0o602]) {
    fs.chmodSync(file, mode);
    assert.throws(() => D.readLedger(file), /written by other users/, mode.toString(8));
    assert.throws(() => D.recordDomain(file, { contract, genesis: later }), /written by other users/, mode.toString(8));
  }
  fs.chmodSync(file, 0o600);
  assert.strictEqual(D.recordDomain(file, { contract, genesis: later }).genesis, later);
});

test('a domain ledger that is not a regular file is refused', (t) => {
  const dir = place(t);
  const file = path.join(dir, 'domains.json');
  fs.mkdirSync(file);
  assert.throws(() => D.readLedger(file), /not a regular file|EISDIR/);
  if (process.platform !== 'win32') {
    const fifo = path.join(dir, 'fifo.json');
    execFileSync('/usr/bin/mkfifo', [fifo]);
    assert.throws(() => D.readLedger(fifo), /not a regular file/);
  }
});

test('the recorded ledger is private to its owner', (t) => {
  const dir = place(t);
  const file = path.join(dir, 'domains.json');
  const old = process.umask(0);
  try {
    D.recordDomain(file, { contract, genesis });
  } finally {
    process.umask(old);
  }
  assert.strictEqual(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepStrictEqual(fs.readdirSync(dir), ['domains.json']);
});

test('a ledger folder others can write is refused', (t) => {
  const dir = place(t);
  const open = path.join(dir, 'open');
  fs.mkdirSync(open);
  for (const mode of [0o777, 0o1777, 0o770]) {
    fs.chmodSync(open, mode);
    assert.throws(() => D.recordDomain(path.join(open, 'domains.json'), { contract, genesis }), /written by other users/, mode.toString(8));
  }
  assert.ok(!fs.existsSync(path.join(open, 'domains.json')));
});

test('a ledger folder below a folder others can change is refused', (t) => {
  const dir = place(t);
  const shared = path.join(dir, 'shared');
  const inner = path.join(shared, 'inner');
  fs.mkdirSync(inner, { recursive: true });
  fs.chmodSync(shared, 0o777);
  assert.throws(() => D.recordDomain(path.join(inner, 'domains.json'), { contract, genesis }), /above the domain ledger can be changed/);
  fs.chmodSync(shared, 0o700);
  const link = path.join(dir, 'via');
  const sharedTwo = path.join(dir, 'shared2');
  fs.mkdirSync(path.join(sharedTwo, 'inner'), { recursive: true });
  fs.chmodSync(sharedTwo, 0o777);
  fs.symlinkSync(path.join(sharedTwo, 'inner'), link);
  assert.throws(() => D.recordDomain(path.join(link, 'domains.json'), { contract, genesis }), /above the domain ledger can be changed/);
});

test('a ledger folder whose access list lets others write is refused', { skip: process.platform !== 'darwin' }, (t) => {
  const dir = place(t);
  const acl = path.join(dir, 'acl');
  fs.mkdirSync(acl, { mode: 0o700 });
  execFileSync('/bin/chmod', ['+a', 'everyone allow add_file,delete_child', acl]);
  assert.throws(() => D.recordDomain(path.join(acl, 'domains.json'), { contract, genesis }), /access control list/);
  const below = path.join(acl, 'below');
  fs.mkdirSync(below, { mode: 0o700 });
  assert.throws(() => D.recordDomain(path.join(below, 'domains.json'), { contract, genesis }), /above the domain ledger can be changed/);
});

test('two writers never both record', (t) => {
  const dir = place(t);
  const file = path.join(dir, 'domains.json');
  const lock = path.join(dir, '.domains.json.lock');
  fs.writeFileSync(lock, '', { mode: 0o600 });
  assert.throws(() => D.recordDomain(file, { contract, genesis }), /another command is recording/);
  assert.ok(!fs.existsSync(file));
  fs.rmSync(lock);
  D.recordDomain(file, { contract, genesis });
  assert.ok(!fs.existsSync(lock));
});

test('every recording that reports success is kept when processes race', async (t) => {
  const dir = place(t);
  const file = path.join(dir, 'domains.json');
  const script = 'const D=require(process.argv[1]);try{D.recordDomain(process.argv[2],{contract:process.argv[3],genesis:process.argv[4]});process.stdout.write("ok")}catch(e){process.stdout.write("no")}';
  const { spawn } = require('child_process');
  const runs = [];
  for (let i = 0; i < 24; i += 1) {
    runs.push(new Promise((resolve) => {
      const p = spawn(process.execPath, ['-e', script, path.resolve(__dirname, '../lib/domain.js'), file, contract, (i + 16).toString(16).repeat(32)]);
      let out = '';
      p.stdout.on('data', (b) => { out += b; });
      p.on('close', () => resolve(out));
    }));
  }
  const outs = await Promise.all(runs);
  const ok = outs.filter((o) => o === 'ok').length;
  assert.ok(ok >= 1);
  assert.strictEqual(D.readLedger(file).deployments.length, ok);
});

test('a ledger path that climbs out of a linked folder is checked where it really lands', (t) => {
  const dir = place(t);
  const a = path.join(dir, 'a');
  const b = path.join(dir, 'b');
  fs.mkdirSync(a, { mode: 0o700 });
  fs.mkdirSync(path.join(b, 'sub'), { recursive: true });
  fs.chmodSync(b, 0o777);
  fs.symlinkSync(path.join(b, 'sub'), path.join(a, 'link'));
  assert.throws(() => D.recordDomain(path.join(a, 'link') + '/../domains.json', { contract, genesis }), /written by other users/);
  assert.ok(!fs.existsSync(path.join(b, 'domains.json')));
  assert.ok(!fs.existsSync(path.join(a, 'domains.json')));
  fs.chmodSync(b, 0o700);
  D.recordDomain(path.join(a, 'link') + '/../domains.json', { contract, genesis });
  assert.ok(fs.existsSync(path.join(b, 'domains.json')));
  assert.throws(() => D.recordDomain(path.join(dir, 'a') + '/', { contract, genesis }), /names a folder/);
});

test('a ledger folder below a folder its group can change is refused', (t) => {
  const dir = place(t);
  const shared = path.join(dir, 'group');
  const inner = path.join(shared, 'inner');
  fs.mkdirSync(inner, { recursive: true, mode: 0o700 });
  fs.chmodSync(shared, 0o770);
  assert.throws(() => D.recordDomain(path.join(inner, 'domains.json'), { contract, genesis }), /above the domain ledger can be changed/);
  fs.chmodSync(shared, 0o1770);
  D.recordDomain(path.join(inner, 'domains.json'), { contract, genesis });
});

test('a ledger folder replaced while recording is refused', (t) => {
  const dir = place(t);
  const inner = path.join(dir, 'inner');
  fs.mkdirSync(inner, { mode: 0o700 });
  const file = path.join(inner, 'domains.json');
  D.recordDomain(file, { contract, genesis });
  const open = fs.openSync;
  let swapped = false;
  fs.openSync = function (p, ...rest) {
    const fd = open.call(this, p, ...rest);
    if (!swapped && String(p).endsWith('.domains.json.lock')) {
      swapped = true;
      fs.renameSync(inner, path.join(dir, 'moved'));
      fs.mkdirSync(inner, { mode: 0o700 });
    }
    return fd;
  };
  try {
    assert.throws(() => D.recordDomain(file, { contract, genesis: later, domain: '777' }), /moved or replaced/);
  } finally {
    fs.openSync = open;
  }
  assert.ok(swapped);
  assert.ok(!fs.existsSync(file));
});

test('a ledger file whose access list lets others write is refused', { skip: process.platform !== 'darwin' }, (t) => {
  const dir = place(t);
  const file = path.join(dir, 'domains.json');
  D.recordDomain(file, { contract, genesis });
  execFileSync('/bin/chmod', ['+a', 'group:everyone allow write,append', file]);
  assert.throws(() => D.readLedger(file), /access control list/);
  assert.throws(() => D.recordDomain(file, { contract, genesis: later }), /access control list/);
  execFileSync('/bin/chmod', ['-N', file]);
  assert.strictEqual(D.recordDomain(file, { contract, genesis: later }).genesis, later);
});

test('a recording that reached the ledger is reported as recorded even when the folder cannot be synced', (t) => {
  const dir = place(t);
  const inner = path.join(dir, 'inner');
  fs.mkdirSync(inner, { mode: 0o700 });
  const file = path.join(inner, 'domains.json');
  fs.chmodSync(inner, 0o300);
  let record;
  try {
    record = D.recordDomain(file, { contract, genesis, domain: '4242' });
  } finally {
    fs.chmodSync(inner, 0o700);
  }
  assert.strictEqual(record.domain, '4242');
  assert.strictEqual(D.readLedger(file).deployments.length, 1);
});

test('a close or cleanup error after the ledger is written never reports a failure or keeps the lock', (t) => {
  const dir = place(t);
  const file = path.join(dir, 'domains.json');
  const open = fs.openSync;
  const close = fs.closeSync;
  let lockFd = null;
  fs.openSync = function (p, ...rest) {
    const fd = open.call(this, p, ...rest);
    if (String(p).endsWith('.domains.json.lock')) lockFd = fd;
    return fd;
  };
  fs.closeSync = function (fd) {
    close.call(this, fd);
    if (fd === lockFd || (typeof fd === 'number' && fd !== lockFd && fs.existsSync(file))) {
      const err = new Error('EIO: i/o error, close');
      err.code = 'EIO';
      throw err;
    }
  };
  let record;
  try {
    record = D.recordDomain(file, { contract, genesis, domain: '4242' });
  } finally {
    fs.openSync = open;
    fs.closeSync = close;
  }
  assert.strictEqual(record.domain, '4242');
  assert.ok(!fs.existsSync(path.join(dir, '.domains.json.lock')));
  assert.strictEqual(D.recordDomain(file, { contract, genesis: later }).genesis, later);
});

test('the domain ledger refuses to run on Windows where folder owners and modes cannot be checked', (t) => {
  const dir = place(t);
  const was = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
  try {
    assert.throws(() => D.recordDomain(path.join(dir, 'domains.json'), { contract, genesis }), /Windows/);
  } finally {
    Object.defineProperty(process, 'platform', was);
  }
});
