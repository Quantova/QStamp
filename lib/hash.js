// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const crypto = require('crypto');
const fs = require('fs');

const MAX_FILE_BYTES = 2 ** 40;
const CHUNK_BYTES = 1024 * 1024;
const NOFOLLOW = fs.constants.O_NOFOLLOW || 0;
const NONBLOCK = fs.constants.O_NONBLOCK || 0;
const ALGORITHMS = Object.freeze({
  'sha3-256': 1,
  sha256: 2,
});

function algorithmId(name) {
  if (typeof name !== 'string' || !Object.prototype.hasOwnProperty.call(ALGORITHMS, name)) {
    throw new Error('unsupported digest algorithm ' + String(name));
  }
  return ALGORITHMS[name];
}

function sha3(...parts) {
  const h = crypto.createHash('sha3-256');
  for (const part of parts) h.update(part);
  return h.digest();
}

function digestBytes(bytes, alg = 'sha3-256') {
  algorithmId(alg);
  if (!(bytes instanceof Uint8Array)) throw new Error('the input must be bytes');
  return crypto.createHash(alg).update(bytes).digest();
}

function fileError(message, cause) {
  const e = new Error(message, cause === undefined ? undefined : { cause });
  e.code = 'QSTAMP_FILE';
  return e;
}

function openRegular(path, maxBytes, what) {
  const label = what || 'file';
  const limit = maxBytes === undefined ? MAX_FILE_BYTES : maxBytes;
  if (typeof path !== 'string' || path.length === 0 || path.includes('\0')) throw fileError('the ' + label + ' must be named by a path');
  let fd;
  try {
    fd = fs.openSync(path, fs.constants.O_RDONLY | NOFOLLOW | NONBLOCK);
  } catch (e) {
    if (e && e.code === 'ELOOP') throw fileError('the ' + label + ' ' + path + ' is a symbolic link, which is not followed', e);
    if (e && e.code === 'ENOENT') throw fileError('the ' + label + ' ' + path + ' does not exist', e);
    throw fileError('the ' + label + ' ' + path + ' could not be opened', e);
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw fileError('the ' + label + ' ' + path + ' is not a regular file');
    if (st.size > limit) throw fileError('the ' + label + ' ' + path + ' is larger than ' + limit + ' bytes');
    return { fd, size: st.size };
  } catch (e) {
    fs.closeSync(fd);
    throw e;
  }
}

function readChunk(fd, buf, position) {
  return new Promise((resolve, reject) => {
    fs.read(fd, buf, 0, buf.length, position, (err, n) => (err ? reject(err) : resolve(n)));
  });
}

async function eachChunk(fd, size, path, label, onChunk) {
  const buf = Buffer.allocUnsafe(Math.max(1, Math.min(CHUNK_BYTES, size + 1)));
  let at = 0;
  for (;;) {
    let n;
    try {
      n = await readChunk(fd, buf, at);
    } catch (e) {
      throw fileError('the ' + label + ' ' + path + ' could not be read', e);
    }
    if (n === 0) break;
    at += n;
    if (at > size) throw fileError('the ' + label + ' ' + path + ' grew while it was read');
    onChunk(buf.subarray(0, n));
  }
  if (at !== size) throw fileError('the ' + label + ' ' + path + ' shrank while it was read');
}

async function readRegular(path, maxBytes, what) {
  const label = what || 'file';
  const { fd, size } = openRegular(path, maxBytes, label);
  try {
    const parts = [];
    await eachChunk(fd, size, path, label, (chunk) => parts.push(Buffer.from(chunk)));
    return Buffer.concat(parts);
  } finally {
    fs.closeSync(fd);
  }
}

async function digestFile(path, alg = 'sha3-256') {
  algorithmId(alg);
  const { fd, size } = openRegular(path, MAX_FILE_BYTES, 'file');
  try {
    const h = crypto.createHash(alg);
    await eachChunk(fd, size, path, 'file', (chunk) => h.update(chunk));
    return h.digest();
  } finally {
    fs.closeSync(fd);
  }
}

function parseDigest(value) {
  if (value instanceof Uint8Array) {
    if (value.length !== 32) throw new Error('a digest is 32 bytes');
    return Buffer.from(value);
  }
  if (typeof value !== 'string' || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error('a digest is 32 bytes or 64 hex characters');
  }
  return Buffer.from(value.toLowerCase(), 'hex');
}

module.exports = { ALGORITHMS, algorithmId, sha3, digestBytes, digestFile, readRegular, parseDigest, MAX_FILE_BYTES };
