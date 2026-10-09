#!/usr/bin/env node
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const qstamp = require('..');
const pkg = require('../package.json');

const CLI_PENDING = 'qstamp-cli-pending/1';
const MAX_RECEIPT_BYTES = 1024 * 1024;
const MAX_PENDING_BYTES = 512 * 1024 * 1024;
const RECEIPT_SUFFIX = '.qstamp.json';

const USAGE = [
  'Qstamp ' + pkg.version,
  '',
  'qstamp hash <file...> [--alg sha3-256|sha256]',
  'qstamp stamp <file...> --seed-file <path> --index <n> [--kind <kind>] [--alg <alg>] [--rpc <url>] [--out <dir>] [--max-fee <quon>] [--force]',
  'qstamp complete <pending.json> [--tx <id>] [--rpc <url>] [--force]',
  'qstamp verify <receipt.json> (--file <path> | --digest <hex>) [--rpc <url>]... [--json]',
  'qstamp kinds',
].join('\n');

const FLAGS = {
  hash: { alg: 'value' },
  stamp: { 'seed-file': 'value', index: 'value', kind: 'value', alg: 'value', rpc: 'value', out: 'value', 'max-fee': 'value', network: 'value', force: 'bool' },
  complete: { rpc: 'value', tx: 'value', force: 'bool' },
  verify: { file: 'value', digest: 'value', rpc: 'multi', json: 'bool' },
  kinds: {},
  help: {},
  version: {},
};

function safe(value) {
  return String(value).replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, ' ');
}

function usageError(message) {
  const e = new Error(message);
  e.usage = true;
  return e;
}

function parse(command, argv) {
  const allowed = Object.prototype.hasOwnProperty.call(FLAGS, command) ? FLAGS[command] : null;
  if (!allowed) throw usageError('unknown command ' + command + '\n\n' + USAGE);
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) {
      positional.push(a);
      continue;
    }
    const name = a.slice(2);
    if (name.includes('=') || !Object.prototype.hasOwnProperty.call(allowed, name)) {
      throw usageError('--' + name + ' is not an option of qstamp ' + command);
    }
    if (allowed[name] === 'bool') {
      flags[name] = true;
      continue;
    }
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) throw usageError('--' + name + ' needs a value');
    i += 1;
    if (allowed[name] === 'multi') (flags[name] = flags[name] || []).push(value);
    else if (flags[name] !== undefined) throw usageError('--' + name + ' was given twice');
    else flags[name] = value;
  }
  return { positional, flags };
}

function hexNibble(code) {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 97 && code <= 102) return code - 87;
  if (code >= 65 && code <= 70) return code - 55;
  return -1;
}

function readSeed(file) {
  if (!file) throw usageError('a signing key file is required, pass --seed-file or set QSTAMP_SEED_FILE');
  const nofollow = fs.constants.O_NOFOLLOW || 0;
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | nofollow);
  } catch (e) {
    throw usageError(e.code === 'ELOOP' ? 'the key file must not be a symbolic link' : 'the key file ' + file + ' could not be opened');
  }
  const raw = Buffer.allocUnsafeSlow(130);
  const seed = new Uint8Array(32);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw usageError('the key file must be a regular file');
    if (process.platform !== 'win32') {
      if ((st.mode & 0o077) !== 0) throw usageError('the key file ' + file + ' is readable by other users, restrict it with chmod 600');
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw usageError('the key file ' + file + ' is not owned by the current user');
    }
    const n = fs.readSync(fd, raw, 0, raw.length, 0);
    let end = n;
    while (end > 0 && (raw[end - 1] === 10 || raw[end - 1] === 13 || raw[end - 1] === 32)) end -= 1;
    if (end !== 64) throw usageError('the key file must hold a 32 byte seed as 64 hex characters');
    for (let i = 0; i < 32; i += 1) {
      const hi = hexNibble(raw[2 * i]);
      const lo = hexNibble(raw[2 * i + 1]);
      if (hi < 0 || lo < 0) throw usageError('the key file must hold a 32 byte seed as 64 hex characters');
      seed[i] = (hi << 4) | lo;
    }
    return seed;
  } catch (e) {
    seed.fill(0);
    throw e;
  } finally {
    raw.fill(0);
    fs.closeSync(fd);
  }
}

function wholeNumber(value, name) {
  if (!/^(0|[1-9][0-9]{0,15})$/.test(String(value))) throw usageError('--' + name + ' must be a whole number');
  const n = Number(value);
  if (!Number.isSafeInteger(n)) throw usageError('--' + name + ' is too large');
  return n;
}

function statOf(file) {
  try {
    return fs.lstatSync(file);
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
}

function atomicWrite(dest, text) {
  const tmp = path.join(path.dirname(dest), '.' + path.basename(dest) + '.' + crypto.randomBytes(6).toString('hex') + '.tmp');
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try {
    fs.fchmodSync(fd, 0o600);
    fs.writeSync(fd, text);
    fs.fsyncSync(fd);
  } catch (e) {
    fs.closeSync(fd);
    fs.rmSync(tmp, { force: true });
    throw e;
  }
  fs.closeSync(fd);
  try {
    fs.renameSync(tmp, dest);
  } catch (e) {
    fs.rmSync(tmp, { force: true });
    throw e;
  }
}

function reserve(dest, force) {
  const existing = statOf(dest);
  if (existing && existing.isSymbolicLink()) throw usageError('refusing to write a receipt through the symbolic link ' + dest);
  if (existing && !existing.isFile()) throw usageError('something other than a receipt already exists at ' + dest);
  if (existing && !force) throw usageError('a receipt already exists at ' + dest + ', pass --force to replace it');
  if (existing) return false;
  fs.closeSync(fs.openSync(dest, 'wx', 0o600));
  return true;
}

function writeReceipt(dest, receipt, replace) {
  const st = statOf(dest);
  if (st && st.isSymbolicLink()) throw new Error('refusing to write a receipt through the symbolic link ' + dest);
  if (st && !st.isFile()) throw new Error('something other than a receipt exists at ' + dest);
  if (st && st.size > 0 && !replace) throw new Error('a file already exists at ' + dest + ' and was not replaced');
  atomicWrite(dest, JSON.stringify(receipt, null, 2) + '\n');
}

function writePrivate(file, value) {
  const st = statOf(file);
  if (st && !st.isFile()) throw new Error('refusing to write the pending file through ' + file);
  atomicWrite(file, JSON.stringify(value, null, 2) + '\n');
}

function readJson(file, maxBytes, what) {
  const st = fs.statSync(file);
  if (!st.isFile()) throw usageError('the ' + what + ' must be a regular file');
  if (st.size > maxBytes) throw usageError('the ' + what + ' is larger than ' + maxBytes + ' bytes');
  const text = fs.readFileSync(file, 'utf8');
  try {
    return JSON.parse(text);
  } catch (e) {
    const err = new Error('the ' + what + ' ' + file + ' is not valid JSON');
    err.invalid = true;
    throw err;
  }
}

async function cmdHash(positional, flags) {
  if (positional.length === 0) throw usageError('name at least one file');
  const alg = flags.alg || 'sha3-256';
  for (const file of positional) {
    const d = await qstamp.digestFile(file, alg);
    process.stdout.write(d.toString('hex') + '  ' + file + '\n');
  }
  return 0;
}

function saveReceipts(outputs, receipts, replace) {
  const unwritten = [];
  receipts.forEach((r, i) => {
    try {
      writeReceipt(outputs[i], r, replace);
      process.stdout.write('receipt ' + outputs[i] + '\n');
    } catch (e) {
      unwritten.push({ file: outputs[i], error: e.message, receipt: r });
    }
  });
  if (unwritten.length) {
    process.stdout.write(JSON.stringify(unwritten, null, 2) + '\n');
    throw new Error(unwritten.length + ' receipt(s) could not be written, they are printed above and must be kept');
  }
}

async function cmdStamp(positional, flags) {
  if (positional.length === 0) throw usageError('name at least one file to stamp');
  if (flags.index === undefined) throw usageError('--index is required');
  const index = wholeNumber(flags.index, 'index');
  const alg = flags.alg || 'sha3-256';
  const outDir = flags.out;
  const outputs = positional.map((file) => path.resolve(outDir || path.dirname(file), path.basename(file) + RECEIPT_SUFFIX));
  if (new Set(outputs).size !== outputs.length) throw usageError('two inputs would share one receipt name, stamp them separately or use --out');
  const records = [];
  for (const file of positional) records.push({ alg, digest: (await qstamp.digestFile(file, alg)).toString('hex'), salt: crypto.randomBytes(32).toString('hex') });
  if (outDir) fs.mkdirSync(outDir, { recursive: true });
  const pendingFile = path.resolve(outDir || path.dirname(positional[0]), 'qstamp-pending-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex') + '.json');
  const created = [];
  const seed = readSeed(flags['seed-file'] || process.env.QSTAMP_SEED_FILE);
  let submitted = false;
  let unconfirmed = false;
  try {
    for (const dest of outputs) if (reserve(dest, !!flags.force)) created.push(dest);
    writePrivate(pendingFile, { format: CLI_PENDING, outputs, records, pending: null });
    const receipts = await qstamp.stamp({
      network: flags.network || 'testnet',
      rpc: flags.rpc,
      seed,
      index,
      kind: flags.kind || 'file',
      records,
      maxFee: flags['max-fee'] ? String(wholeNumber(flags['max-fee'], 'max-fee')) : undefined,
      onPending: (pending) => {
        submitted = true;
        writePrivate(pendingFile, { format: CLI_PENDING, outputs, records, pending });
        process.stdout.write('submitted ' + pending.tx + '\n');
      },
    });
    saveReceipts(outputs, receipts, !!flags.force);
    fs.unlinkSync(pendingFile);
    process.stdout.write('stamped ' + receipts.length + ' record(s) at height ' + receipts[0].anchor.height + ' in ' + receipts[0].anchor.tx + '\n');
    return 0;
  } catch (e) {
    if (!submitted && e.code === 'QSTAMP_UNCONFIRMED' && e.pending) {
      unconfirmed = true;
      writePrivate(pendingFile, { format: CLI_PENDING, outputs, records, pending: e.pending });
      e.message += '\nthe network did not confirm whether the stamp was sent. ' + pendingFile + ' keeps the records and salts. '
        + 'If a transaction from ' + e.pending.sender + ' to the stamp contract appears, run qstamp complete ' + pendingFile + ' --tx <transaction id>';
    } else if (!submitted) {
      for (const dest of created) fs.rmSync(dest, { force: true });
      fs.rmSync(pendingFile, { force: true });
    } else {
      if (e.pending) writePrivate(pendingFile, { format: CLI_PENDING, outputs, records, pending: e.pending });
      e.message += '\nthe stamp was submitted, keep ' + pendingFile + ' and run qstamp complete ' + pendingFile;
    }
    if (unconfirmed) for (const dest of created) fs.rmSync(dest, { force: true });
    throw e;
  } finally {
    seed.fill(0);
  }
}

async function cmdComplete(positional, flags) {
  if (positional.length !== 1) throw usageError('name exactly one pending file');
  const saved = readJson(positional[0], MAX_PENDING_BYTES, 'pending file');
  if (!saved || saved.format !== CLI_PENDING || !saved.pending || typeof saved.pending !== 'object' || !Array.isArray(saved.outputs)) {
    throw usageError('the file is not a submitted qstamp pending file');
  }
  const outputs = saved.outputs.map((o) => {
    if (typeof o !== 'string' || !path.isAbsolute(o)) throw usageError('the pending file names an invalid receipt path');
    const base = path.basename(o);
    if (!base.endsWith(RECEIPT_SUFFIX) || base.startsWith('.') || base.length <= RECEIPT_SUFFIX.length) {
      throw usageError('the pending file names a receipt path that does not end in ' + RECEIPT_SUFFIX);
    }
    return path.normalize(o);
  });
  if (new Set(outputs).size !== outputs.length) throw usageError('the pending file names the same receipt twice');
  const pending = Object.assign({}, saved.pending);
  if (flags.tx !== undefined) {
    if (!/^QTX1[0-9A-Z]{20,120}$/.test(flags.tx)) throw usageError('--tx must be a transaction id');
    if (pending.tx && pending.tx !== flags.tx) throw usageError('the pending file already names a different transaction');
    pending.tx = flags.tx;
  }
  const receipts = await qstamp.complete(pending, { rpc: flags.rpc });
  if (receipts.length !== outputs.length) throw new Error('the pending file is inconsistent');
  saveReceipts(outputs, receipts, !!flags.force);
  fs.unlinkSync(positional[0]);
  process.stdout.write('completed ' + receipts.length + ' receipt(s) at height ' + receipts[0].anchor.height + '\n');
  return 0;
}

async function cmdVerify(positional, flags) {
  if (positional.length !== 1) throw usageError('name exactly one receipt');
  if ((flags.file === undefined) === (flags.digest === undefined)) throw usageError('pass exactly one of --file or --digest so the record is checked');
  const receipt = readJson(positional[0], MAX_RECEIPT_BYTES, 'receipt');
  const result = await qstamp.verify(receipt, { file: flags.file, digest: flags.digest, clients: flags.rpc });
  if (flags.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    for (const c of result.checks) process.stdout.write((c.ok ? 'pass ' : 'FAIL ') + safe(c.name) + '  ' + safe(c.detail) + '\n');
    const chain = receipt && receipt.chain && typeof receipt.chain.id === 'string' ? receipt.chain.id : 'unknown';
    process.stdout.write('chain ' + chain + '\n');
    process.stdout.write('endpoints ' + (safe(result.endpoints.join(', ')) || 'none') + '\n');
    if (!result.officialEndpoints) process.stdout.write('notice  chain data came from an endpoint that is not the official one for this network\n');
    if (chain === qstamp.NETWORKS.testnet.chainId) process.stdout.write('notice  this is a test network receipt and carries no evidential weight\n');
    if (result.status === 'valid') {
      const t = new Date(receipt.anchor.time * 1000);
      const when = Number.isNaN(t.getTime()) ? String(receipt.anchor.time) : t.toISOString();
      process.stdout.write('VALID  stamped no later than ' + when + ' in block ' + receipt.anchor.height + ' by ' + receipt.anchor.sender + '\n');
    } else if (result.status === 'indeterminate') {
      process.stdout.write('INDETERMINATE  the chain could not be consulted, try again or use another endpoint\n');
    } else {
      process.stdout.write('INVALID\n');
    }
  }
  return result.status === 'valid' ? 0 : result.status === 'indeterminate' ? 2 : 1;
}

async function main() {
  const argv = process.argv.slice(2);
  const command = argv[0] === undefined || argv[0] === '--help' ? 'help' : argv[0] === '--version' ? 'version' : argv[0];
  const { positional, flags } = parse(command, argv.slice(1));
  if (command === 'help') {
    process.stdout.write(USAGE + '\n');
    return 0;
  }
  if (command === 'version') {
    process.stdout.write(pkg.version + '\n');
    return 0;
  }
  if (command === 'hash') return cmdHash(positional, flags);
  if (command === 'stamp') return cmdStamp(positional, flags);
  if (command === 'complete') return cmdComplete(positional, flags);
  if (command === 'verify') return cmdVerify(positional, flags);
  for (const [name, value] of Object.entries(qstamp.KINDS)) process.stdout.write(value + '  ' + name + '\n');
  return 0;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    process.stderr.write('qstamp: ' + String(e && e.message ? e.message : e).split('\n').map(safe).join('\n') + '\n');
    process.exit(e && e.usage ? 64 : 1);
  },
);
