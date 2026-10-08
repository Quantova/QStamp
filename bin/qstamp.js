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

const USAGE = [
  'Qstamp ' + pkg.version,
  '',
  'qstamp hash <file...> [--alg sha3-256|sha256]',
  'qstamp stamp <file...> --seed-file <path> --index <n> [--kind <kind>] [--alg <alg>] [--rpc <url>] [--out <dir>] [--max-fee <quon>] [--force]',
  'qstamp complete <pending.json> [--rpc <url>]',
  'qstamp verify <receipt.json> (--file <path> | --digest <hex>) [--rpc <url>]... [--json]',
  'qstamp kinds',
].join('\n');

const FLAGS = {
  hash: { alg: 'value' },
  stamp: { 'seed-file': 'value', index: 'value', kind: 'value', alg: 'value', rpc: 'value', out: 'value', 'max-fee': 'value', network: 'value', force: 'bool' },
  complete: { rpc: 'value' },
  verify: { file: 'value', digest: 'value', rpc: 'multi', json: 'bool' },
  kinds: {},
  help: {},
  version: {},
};

function usageError(message) {
  const e = new Error(message);
  e.usage = true;
  return e;
}

function parse(command, argv) {
  const allowed = FLAGS[command];
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
  const st = fs.lstatSync(file);
  if (!st.isFile()) throw usageError('the key file must be a regular file');
  if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) {
    throw usageError('the key file ' + file + ' is readable by other users, restrict it with chmod 600');
  }
  const raw = Buffer.allocUnsafeSlow(130);
  const seed = new Uint8Array(32);
  const fd = fs.openSync(file, 'r');
  try {
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

function reserve(dest, force) {
  let existing = null;
  try {
    existing = fs.lstatSync(dest);
  } catch (e) {
    existing = null;
  }
  if (existing && existing.isSymbolicLink()) throw usageError('refusing to write a receipt through the symbolic link ' + dest);
  if (existing && !force) throw usageError('a receipt already exists at ' + dest + ', pass --force to replace it');
  fs.closeSync(fs.openSync(dest, existing ? 'w' : 'wx', 0o600));
  return !existing;
}

function writeReceipt(dest, receipt) {
  let st = null;
  try {
    st = fs.lstatSync(dest);
  } catch (e) {
    st = null;
  }
  if (st && st.isSymbolicLink()) throw new Error('refusing to write a receipt through the symbolic link ' + dest);
  fs.writeFileSync(dest, JSON.stringify(receipt, null, 2) + '\n', { mode: 0o600, flag: st ? 'w' : 'wx' });
  fs.chmodSync(dest, 0o600);
}

function writePrivate(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(file, 0o600);
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

function saveReceipts(outputs, receipts) {
  const unwritten = [];
  receipts.forEach((r, i) => {
    try {
      writeReceipt(outputs[i], r);
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
  const outputs = positional.map((file) => path.resolve(outDir || path.dirname(file), path.basename(file) + '.qstamp.json'));
  if (new Set(outputs).size !== outputs.length) throw usageError('two inputs would share one receipt name, stamp them separately or use --out');
  const records = [];
  for (const file of positional) records.push({ alg, digest: (await qstamp.digestFile(file, alg)).toString('hex'), salt: crypto.randomBytes(32).toString('hex') });
  if (outDir) fs.mkdirSync(outDir, { recursive: true });
  const pendingFile = path.resolve(outDir || path.dirname(positional[0]), 'qstamp-pending-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex') + '.json');
  const created = [];
  const seed = readSeed(flags['seed-file'] || process.env.QSTAMP_SEED_FILE);
  let submitted = false;
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
    saveReceipts(outputs, receipts);
    fs.unlinkSync(pendingFile);
    process.stdout.write('stamped ' + receipts.length + ' record(s) at height ' + receipts[0].anchor.height + ' in ' + receipts[0].anchor.tx + '\n');
    return 0;
  } catch (e) {
    if (!submitted) {
      for (const dest of created) fs.rmSync(dest, { force: true });
      fs.rmSync(pendingFile, { force: true });
    } else {
      if (e.pending) writePrivate(pendingFile, { format: CLI_PENDING, outputs, records, pending: e.pending });
      e.message += '\nthe stamp was submitted, keep ' + pendingFile + ' and run qstamp complete ' + pendingFile;
    }
    throw e;
  } finally {
    seed.fill(0);
  }
}

async function cmdComplete(positional, flags) {
  if (positional.length !== 1) throw usageError('name exactly one pending file');
  const saved = JSON.parse(fs.readFileSync(positional[0], 'utf8'));
  if (!saved || saved.format !== CLI_PENDING || !saved.pending || !Array.isArray(saved.outputs)) {
    throw usageError('the file is not a submitted qstamp pending file');
  }
  const receipts = await qstamp.complete(saved.pending, { rpc: flags.rpc });
  if (receipts.length !== saved.outputs.length) throw new Error('the pending file is inconsistent');
  saveReceipts(saved.outputs, receipts);
  fs.unlinkSync(positional[0]);
  process.stdout.write('completed ' + receipts.length + ' receipt(s) at height ' + receipts[0].anchor.height + '\n');
  return 0;
}

async function cmdVerify(positional, flags) {
  if (positional.length !== 1) throw usageError('name exactly one receipt');
  if ((flags.file === undefined) === (flags.digest === undefined)) throw usageError('pass exactly one of --file or --digest so the record is checked');
  const receipt = JSON.parse(fs.readFileSync(positional[0], 'utf8'));
  const result = await qstamp.verify(receipt, { file: flags.file, digest: flags.digest, clients: flags.rpc });
  if (flags.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    for (const c of result.checks) process.stdout.write((c.ok ? 'pass ' : 'FAIL ') + c.name + '  ' + c.detail + '\n');
    const chain = receipt && receipt.chain && typeof receipt.chain.id === 'string' ? receipt.chain.id : 'unknown';
    process.stdout.write('chain ' + chain + '\n');
    process.stdout.write('endpoints ' + (result.endpoints.join(', ') || 'none') + '\n');
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
    process.stderr.write('qstamp: ' + e.message + '\n');
    process.exit(2);
  },
);
