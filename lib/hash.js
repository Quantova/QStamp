// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const crypto = require('crypto');
const fs = require('fs');

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

function digestFile(path, alg = 'sha3-256') {
  algorithmId(alg);
  return new Promise((resolve, reject) => {
    const h = crypto.createHash(alg);
    const stream = fs.createReadStream(path);
    stream.on('error', reject);
    stream.on('data', (chunk) => h.update(chunk));
    stream.on('end', () => resolve(h.digest()));
  });
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

module.exports = { ALGORITHMS, algorithmId, sha3, digestBytes, digestFile, parseDigest };
