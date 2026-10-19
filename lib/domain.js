// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const crypto = require('crypto');
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { decode } = require('./bech32m');

const U64_MAX = (1n << 64n) - 1n;
const LEDGER_FORMAT = 'qstamp-deployment-domains/1';
const MAX_LEDGER_BYTES = 4 * 1024 * 1024;
const MAX_ENTRIES = 10000;
const DIGITS = /^[1-9][0-9]{0,19}$/;
const GENESIS = /^[0-9a-f]{64}$/;

function deploymentDomain() {
  for (;;) {
    const value = crypto.randomBytes(8).readBigUInt64BE(0);
    if (value !== 0n) return value.toString(10);
  }
}

function checkDomain(domain) {
  const text = typeof domain === 'bigint' ? domain.toString(10) : domain;
  if (typeof text !== 'string' || !DIGITS.test(text) || BigInt(text) > U64_MAX) {
    throw new Error('a deployment domain is a whole number from 1 to 18446744073709551615 written in decimal');
  }
  return text;
}

function checkContract(contract) {
  try {
    if (typeof contract !== 'string') throw new Error('type');
    decode(contract, 'Q', 32);
  } catch (e) {
    throw new Error('the contract is not a Quantova address');
  }
  return contract.toUpperCase();
}

function checkGenesis(genesis) {
  if (typeof genesis !== 'string' || !GENESIS.test(genesis)) throw new Error('the genesis hash must be 64 lowercase hexadecimal characters');
  return genesis;
}

const READ_FLAGS = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);

const WRITE_RIGHTS = /\b(add_file|add_subdirectory|delete_child|delete|write|append|writeattr|writeextattr|writesecurity|chown)\b/;

function listing(file, args, dir) {
  try {
    return execFileSync(file, args, { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    throw new Error('the permissions of the folder ' + String(dir).slice(0, 200) + ' could not be read');
  }
}

function aclLetsOthersWrite(dir) {
  if (process.platform === 'win32') return false;
  if (process.platform === 'darwin') {
    return listing('/bin/ls', ['-lde', dir], dir).split('\n').some((l) => /^\s*\d+: /.test(l) && / allow /.test(l) && WRITE_RIGHTS.test(l));
  }
  for (const tool of ['/usr/bin/getfacl', '/bin/getfacl']) {
    if (fs.existsSync(tool)) {
      return listing(tool, ['-cp', dir], dir).split('\n').some((l) => /^(default:)?(user|group):[^:]+:[r-]w/.test(l.trim()));
    }
  }
  let version = '';
  try {
    version = execFileSync('/bin/ls', ['--version'], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
  } catch (e) {
    version = '';
  }
  if (!/GNU coreutils/.test(version)) throw new Error('access control lists cannot be read on this system, install getfacl so the domain ledger folder can be checked');
  return /^.{10}\+/.test(listing('/bin/ls', ['-ld', dir], dir));
}

function exposedPlace(dir, ownerUid, depth, includeLast) {
  const self = typeof process.getuid === 'function' ? process.getuid() : null;
  const safe = (p, st) => (self === null || st.uid === 0 || st.uid === self || st.uid === ownerUid) && !((st.mode & 0o002) && !(st.mode & 0o1000)) && !((st.mode & 0o020) && !(st.mode & 0o1000) && !(st.uid === 0 && st.gid === 0)) && !aclLetsOthersWrite(p);
  if (depth > 32) throw new Error('the domain ledger folder is reached through too many symbolic links');
  const full = path.resolve(dir);
  const parts = full.split(path.sep).filter(Boolean);
  let cur = path.parse(full).root;
  if (!safe(cur, fs.statSync(cur))) return cur;
  for (let i = 0; i < parts.length; i += 1) {
    const next = path.join(cur, parts[i]);
    const last = i === parts.length - 1;
    const st = fs.lstatSync(next);
    if (st.isSymbolicLink()) {
      const target = path.resolve(path.dirname(next), fs.readlinkSync(next));
      const bad = exposedPlace(target, ownerUid, depth + 1, !last || includeLast);
      if (bad) return bad;
      cur = fs.realpathSync(target);
      continue;
    }
    if ((!last || includeLast) && !safe(next, st)) return next;
    cur = next;
  }
  return null;
}

function ownFolder(file) {
  const name = path.basename(file);
  if (name === '' || name === '.' || name === '..' || file.endsWith('/') || file.endsWith(path.sep)) throw new Error('the domain ledger path names a folder, give the path of a file');
  let dir;
  try {
    dir = fs.realpathSync.native(path.dirname(file));
  } catch (e) {
    throw new Error('the folder of the domain ledger could not be opened');
  }
  const st = fs.statSync(dir);
  const self = typeof process.getuid === 'function' ? process.getuid() : null;
  if (!st.isDirectory()) throw new Error('the folder of the domain ledger is not a folder');
  if (self !== null && st.uid !== self) throw new Error('the folder of the domain ledger belongs to another user');
  if (st.mode & 0o022) throw new Error('the folder of the domain ledger can be written by other users');
  if (aclLetsOthersWrite(dir)) throw new Error('the folder of the domain ledger carries an access control list that lets others write');
  const above = exposedPlace(dir, self, 0, false);
  if (above) throw new Error('the folder ' + above.slice(0, 200) + ' above the domain ledger can be changed by another user');
  return { dir, target: path.join(dir, name), dev: st.dev, ino: st.ino };
}

function syncFolder(dir) {
  let fd;
  try {
    fd = fs.openSync(dir, 'r');
    fs.fsyncSync(fd);
  } catch (e) {
    return false;
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch (e) {
        void e;
      }
    }
  }
  return true;
}

function samePlace(place) {
  let now;
  try {
    now = fs.realpathSync.native(place.dir) === place.dir ? fs.lstatSync(place.dir) : null;
  } catch (e) {
    now = null;
  }
  if (!now || !now.isDirectory() || now.dev !== place.dev || now.ino !== place.ino) throw new Error('the folder of the domain ledger was moved or replaced while recording');
}

function readLedger(file) {
  let fd;
  try {
    fd = fs.openSync(file, READ_FLAGS);
  } catch (e) {
    if (e && e.code === 'ENOENT') return { format: LEDGER_FORMAT, deployments: [] };
    if (e && e.code === 'ELOOP') throw new Error('the domain ledger is a symbolic link');
    throw e;
  }
  let text;
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new Error('the domain ledger is not a regular file');
    if (stat.size > MAX_LEDGER_BYTES) throw new Error('the domain ledger is too large');
    const self = typeof process.getuid === 'function' ? process.getuid() : null;
    if (self !== null && stat.uid !== self) throw new Error('the domain ledger belongs to another user');
    if (stat.mode & 0o022) throw new Error('the domain ledger can be written by other users');
    if (aclLetsOthersWrite(file)) throw new Error('the domain ledger carries an access control list that lets others write');
    const buf = Buffer.alloc(stat.size);
    let off = 0;
    while (off < buf.length) {
      const n = fs.readSync(fd, buf, off, buf.length - off, off);
      if (n === 0) break;
      off += n;
    }
    text = buf.subarray(0, off).toString('utf8');
  } finally {
    fs.closeSync(fd);
  }
  let ledger;
  try {
    ledger = JSON.parse(text);
  } catch (e) {
    throw new Error('the domain ledger is not valid JSON');
  }
  if (!ledger || typeof ledger !== 'object' || ledger.format !== LEDGER_FORMAT || !Array.isArray(ledger.deployments) || ledger.deployments.length > MAX_ENTRIES) {
    throw new Error('the domain ledger is not a ' + LEDGER_FORMAT + ' file');
  }
  for (const d of ledger.deployments) {
    if (!d || typeof d !== 'object') throw new Error('the domain ledger holds a malformed entry');
    checkContract(d.contract);
    checkGenesis(d.genesis);
    checkDomain(d.domain);
  }
  return ledger;
}

function recordDomain(file, entry) {
  if (typeof file !== 'string' || file.length === 0) throw new Error('give the path of the domain ledger');
  const e = entry || {};
  const contract = checkContract(e.contract);
  const genesis = checkGenesis(e.genesis);
  const domain = e.domain === undefined ? deploymentDomain() : checkDomain(e.domain);
  const place = ownFolder(file);
  const { dir, target } = place;
  const lock = path.join(dir, '.' + path.basename(target) + '.lock');
  let held;
  try {
    held = fs.openSync(lock, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
  } catch (err) {
    if (err && err.code === 'EEXIST') throw new Error('another command is recording into the domain ledger, wait for it or remove ' + lock + ' if none is running');
    throw err;
  }
  let record;
  try {
    samePlace(place);
    const ledger = readLedger(target);
    for (const d of ledger.deployments) {
      if (d.contract.toUpperCase() !== contract) continue;
      if (d.domain === domain) {
        throw new Error('the domain ' + domain + ' is already recorded for the contract ' + contract + ', so orders signed for that deployment would be accepted again, draw a fresh domain with qstamp domain');
      }
      if (d.genesis === genesis) {
        throw new Error('a deployment of the contract ' + contract + ' on this genesis is already recorded');
      }
    }
    if (ledger.deployments.length >= MAX_ENTRIES) throw new Error('the domain ledger is full');
    record = { contract, genesis, domain, recorded: new Date().toISOString() };
    const next = { format: LEDGER_FORMAT, deployments: ledger.deployments.concat([record]) };
    const tmp = path.join(dir, '.' + path.basename(target) + '.' + crypto.randomBytes(6).toString('hex') + '.tmp');
    try {
      const out = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
      try {
        fs.writeSync(out, JSON.stringify(next, null, 2) + '\n');
        fs.fsyncSync(out);
      } finally {
        fs.closeSync(out);
      }
      samePlace(place);
      fs.renameSync(tmp, target);
    } catch (err) {
      fs.rmSync(tmp, { force: true });
      throw err;
    }
    syncFolder(dir);
  } finally {
    try {
      fs.closeSync(held);
    } catch (e) {
      void e;
    }
    try {
      fs.rmSync(lock, { force: true });
    } catch (e) {
      void e;
    }
  }
  return record;
}

module.exports = { deploymentDomain, recordDomain, readLedger, checkDomain, LEDGER_FORMAT };
