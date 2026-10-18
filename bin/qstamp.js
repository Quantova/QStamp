#!/usr/bin/env node
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const qstamp = require('..');
const { readRegular } = require('../lib/hash');
const D = require('../lib/domain');
const pkg = require('../package.json');

const CLI_PENDING = 'qstamp-cli-pending/1';
const MAX_RECEIPT_BYTES = 1024 * 1024;
const MAX_PENDING_BYTES = 512 * 1024 * 1024;
const RECEIPT_SUFFIX = '.qstamp.json';

const USAGE = [
  'Qstamp ' + pkg.version,
  '',
  'qstamp hash <file...> [--alg sha3-256|sha256]',
  'qstamp stamp <file...> --seed-file <path> --index <n> [--kind <kind>] [--alg <alg>] [--rpc <url>]... [--trust-single-endpoint] [--allow-endpoint <host>]... [--allow-loopback] [--out <dir>] [--max-fee <quon>] [--force]',
  'qstamp complete <pending.json> [--tx <id>] [--rpc <url>]... [--trust-single-endpoint] [--allow-endpoint <host>]... [--allow-loopback] [--force]',
  'qstamp verify <receipt.json> (--file <path> | --digest <hex>) [--expect-sender <address>]... [--rpc <url>]... [--trust-custom-endpoints] [--allow-endpoint <host>]... [--allow-loopback] [--json]',
  'qstamp kinds',
  'qstamp domain [--record <ledger.json> --contract <address> --genesis <hex> [--domain <n>]]',
  '',
  'A receipt is reported VALID only when its anchor is proven, by a finality certificate of the validators or by official endpoints of two different operators.',
  'A receipt confirmed only by one operator or by endpoints you chose is reported UNPROVEN and exits with status 3.',
  'Endpoints other than the official ones are consulted by verify only with --trust-custom-endpoints.',
  'Stamping accepts chain data only when at least two independent endpoints agree, or with --trust-single-endpoint.',
  'domain prints a fresh random 64 bit deployment domain for the issuer and council templates. With --record it also writes the domain, the contract and the genesis hash',
  'to a ledger and refuses a domain that the ledger already holds for the same contract, so an order signed for one deployment is never accepted by another.',
].join('\n');

const FLAGS = {
  hash: { alg: 'value' },
  stamp: { 'seed-file': 'value', index: 'value', kind: 'value', alg: 'value', rpc: 'multi', 'trust-single-endpoint': 'bool', 'allow-endpoint': 'multi', 'allow-loopback': 'bool', out: 'value', 'max-fee': 'value', network: 'value', force: 'bool' },
  complete: { rpc: 'multi', 'trust-single-endpoint': 'bool', 'allow-endpoint': 'multi', 'allow-loopback': 'bool', tx: 'value', force: 'bool' },
  verify: { file: 'value', digest: 'value', 'expect-sender': 'multi', rpc: 'multi', 'trust-single-endpoint': 'bool', 'trust-custom-endpoints': 'bool', 'allow-endpoint': 'multi', 'allow-loopback': 'bool', json: 'bool' },
  kinds: {},
  domain: { record: 'value', contract: 'value', genesis: 'value', domain: 'value' },
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

function endpointOptions(flags) {
  const out = { clients: flags.rpc, trustSingleEndpoint: !!flags['trust-single-endpoint'] };
  if (flags['allow-endpoint']) out.endpointAllowList = flags['allow-endpoint'];
  if (flags['allow-loopback']) out.allowLoopback = true;
  if (flags['trust-custom-endpoints']) out.trustCustomEndpoints = true;
  return out;
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
  const nonblock = fs.constants.O_NONBLOCK || 0;
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | nofollow | nonblock);
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

function strictJson(text) {
  const value = JSON.parse(text);
  const stack = [];
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const top = stack[stack.length - 1];
    if (ch === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      if (top && top.keys && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1));
        if (top.keys.has(key)) throw new Error('the JSON repeats the key ' + JSON.stringify(key));
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j;
    } else if (ch === '{') {
      stack.push({ keys: new Set(), expectKey: true });
    } else if (ch === '[') {
      stack.push({ keys: null });
    } else if (ch === '}' || ch === ']') {
      stack.pop();
    } else if (ch === ',' && top && top.keys) {
      top.expectKey = true;
    }
  }
  return value;
}

async function readJson(file, maxBytes, what, invalid) {
  let bytes;
  try {
    bytes = await readRegular(file, maxBytes, what);
  } catch (e) {
    throw usageError(e && e.code === 'QSTAMP_FILE' ? e.message : 'the ' + what + ' ' + file + ' could not be read');
  }
  try {
    return strictJson(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch (e) {
    const err = new Error('the ' + what + ' ' + file + ' is not valid JSON');
    if (invalid) err.invalid = true;
    else err.usage = true;
    throw err;
  }
}

async function digestOf(file, alg) {
  try {
    return await qstamp.digestFile(file, alg);
  } catch (e) {
    throw usageError(e && e.code === 'QSTAMP_FILE' ? e.message : 'the file ' + file + ' could not be read');
  }
}

function cmdDomain(positional, flags) {
  if (positional.length > 0) throw usageError('qstamp domain takes no file names');
  const recording = flags.record !== undefined;
  if (!recording && (flags.contract !== undefined || flags.genesis !== undefined || flags.domain !== undefined)) {
    throw usageError('--contract, --genesis and --domain are used only with --record');
  }
  if (!recording) {
    process.stdout.write(D.deploymentDomain() + '\n');
    return 0;
  }
  if (flags.contract === undefined || flags.genesis === undefined) throw usageError('--record needs --contract and --genesis');
  let record;
  try {
    record = D.recordDomain(flags.record, { contract: flags.contract, genesis: flags.genesis.toLowerCase(), domain: flags.domain });
  } catch (e) {
    throw usageError(e.message);
  }
  process.stdout.write(record.domain + '\n');
  return 0;
}

async function cmdHash(positional, flags) {
  if (positional.length === 0) throw usageError('name at least one file');
  const alg = flags.alg || 'sha3-256';
  for (const file of positional) {
    if (!Object.prototype.hasOwnProperty.call(qstamp.ALGORITHMS, alg)) throw usageError('unsupported digest algorithm ' + alg);
    const d = await digestOf(file, alg);
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
  if (!Object.prototype.hasOwnProperty.call(qstamp.ALGORITHMS, alg)) throw usageError('unsupported digest algorithm ' + alg);
  for (const file of positional) records.push({ alg, digest: (await digestOf(file, alg)).toString('hex'), salt: crypto.randomBytes(32).toString('hex') });
  if (outDir) fs.mkdirSync(outDir, { recursive: true });
  const pendingFile = path.resolve(outDir || path.dirname(positional[0]), 'qstamp-pending-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex') + '.json');
  const created = [];
  const seed = readSeed(flags['seed-file'] || process.env.QSTAMP_SEED_FILE);
  let submitted = false;
  let unconfirmed = false;
  try {
    for (const dest of outputs) if (reserve(dest, !!flags.force)) created.push(dest);
    writePrivate(pendingFile, { format: CLI_PENDING, outputs, records, pending: null });
    const receipts = await qstamp.stamp(Object.assign(endpointOptions(flags), {
      network: flags.network || 'testnet',
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
    }));
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
  const saved = await readJson(positional[0], MAX_PENDING_BYTES, 'pending file', false);
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
  const receipts = await qstamp.complete(pending, endpointOptions(flags));
  if (receipts.length !== outputs.length) throw new Error('the pending file is inconsistent');
  saveReceipts(outputs, receipts, !!flags.force);
  fs.unlinkSync(positional[0]);
  process.stdout.write('completed ' + receipts.length + ' receipt(s) at height ' + receipts[0].anchor.height + '\n');
  return 0;
}

async function cmdVerify(positional, flags) {
  if (positional.length !== 1) throw usageError('name exactly one receipt');
  if ((flags.file === undefined) === (flags.digest === undefined)) throw usageError('pass exactly one of --file or --digest so the record is checked');
  const receipt = await readJson(positional[0], MAX_RECEIPT_BYTES, 'receipt', true);
  const options = Object.assign(endpointOptions(flags), { digest: flags.digest });
  if (flags.file !== undefined) {
    const alg = receipt && receipt.record && typeof receipt.record.alg === 'string' ? receipt.record.alg : null;
    if (alg !== null && Object.prototype.hasOwnProperty.call(qstamp.ALGORITHMS, alg)) options.digest = (await digestOf(flags.file, alg)).toString('hex');
    else options.file = flags.file;
  }
  if (flags['expect-sender']) options.expectedSender = flags['expect-sender'];
  const result = await qstamp.verify(receipt, options);
  if (flags.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    for (const c of result.checks) process.stdout.write((c.ok ? 'pass ' : 'FAIL ') + safe(c.name) + '  ' + safe(c.detail) + '\n');
    for (const n of result.notices || []) process.stdout.write('notice  ' + safe(n) + '\n');
    const chain = receipt && receipt.chain && typeof receipt.chain.id === 'string' ? receipt.chain.id : 'unknown';
    process.stdout.write('chain ' + safe(chain) + '\n');
    process.stdout.write('endpoints ' + (safe(result.endpoints.join(', ')) || 'none') + '\n');
    if (result.endpoints.length && !result.officialEndpoints) process.stdout.write('notice  chain data came from endpoints that are not the official ones for this network\n');
    if (result.trust && result.trust !== 'none') process.stdout.write('trust ' + safe(result.trust) + '  ' + safe(result.trustDetail) + '\n');
    if (result.revoked && result.revoked.reason) process.stdout.write('REVOKED  the issuer withdrew this record with reason code ' + safe(result.revoked.reason) + '\n');
    if (result.status === 'valid') {
      const t = new Date(receipt.anchor.time * 1000);
      const when = Number.isNaN(t.getTime()) ? String(receipt.anchor.time) : t.toISOString();
      process.stdout.write('VALID  stamped no later than ' + when + ' in block ' + receipt.anchor.height + ' by ' + receipt.anchor.sender + '\n');
    } else if (result.status === 'unproven') {
      process.stdout.write('WARNING  this receipt is NOT proven. The chain data came from ' + (result.trust === 'custom-endpoints' ? 'endpoints you chose' : 'a single operator') + ', which could have invented it. Do not rely on it as evidence.\n');
      process.stdout.write('UNPROVEN  the anchor matches the endpoints consulted, but it was not proven by a finality certificate or by official endpoints of two different operators\n');
    } else if (result.status === 'indeterminate') {
      process.stdout.write('INDETERMINATE  the anchor could be neither confirmed nor refuted, see the checks above and try again later\n');
    } else {
      process.stdout.write('INVALID\n');
    }
  }
  if (result.status === 'valid') return 0;
  if (result.status === 'unproven') return 3;
  return result.status === 'indeterminate' ? 2 : 1;
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
  if (command === 'domain') return cmdDomain(positional, flags);
  for (const [name, value] of Object.entries(qstamp.KINDS)) process.stdout.write(value + '  ' + name + '\n');
  return 0;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    process.stderr.write('qstamp: ' + String(e && e.message ? e.message : e).split('\n').map(safe).join('\n') + '\n');
    process.exit(e && e.invalid ? 1 : 64);
  },
);
