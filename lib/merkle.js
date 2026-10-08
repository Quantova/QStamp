// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { sha3, algorithmId } = require('./hash');
const { addressBytes } = require('./bech32m');
const { kindWord } = require('./wire');

const LEAF_TAG = Buffer.from('QSTAMP/LEAF/V1', 'ascii');
const ROOT_TAG = Buffer.from('QSTAMP/ROOT/V1', 'ascii');
const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);
const ROOT_PREFIX = Buffer.from([0x02]);
const MAX_LEAVES = 1 << 20;
const MAX_PATH = 20;
const SALT_BYTES = 32;

function bytes32(value, what) {
  if (!Buffer.isBuffer(value) || value.length !== 32) throw new Error(what + ' is 32 bytes');
  return value;
}

function leafHash(alg, digest, salt) {
  const id = algorithmId(alg);
  bytes32(digest, 'a digest');
  bytes32(salt, 'a salt');
  return sha3(LEAF_PREFIX, LEAF_TAG, Buffer.from([id]), digest, salt);
}

function nodeHash(left, right) {
  return sha3(NODE_PREFIX, bytes32(left, 'a tree node'), bytes32(right, 'a tree node'));
}

function commitment(root, size, context) {
  bytes32(root, 'a root');
  if (!Number.isSafeInteger(size) || size < 1 || size > MAX_LEAVES) throw new Error('a batch size is out of range');
  if (!context || typeof context !== 'object') throw new Error('a commitment needs its chain context');
  if (typeof context.genesis !== 'string' || !/^[0-9a-f]{64}$/.test(context.genesis)) throw new Error('the genesis hash is malformed');
  const s = Buffer.alloc(8);
  s.writeBigUInt64BE(BigInt(size));
  return sha3(
    ROOT_PREFIX,
    ROOT_TAG,
    Buffer.from(context.genesis, 'hex'),
    addressBytes(context.contract),
    addressBytes(context.sender),
    kindWord(context.kind),
    s,
    root,
  );
}

function splitPoint(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function build(hashes, lo, hi, paths) {
  const n = hi - lo;
  if (n === 1) return hashes[lo];
  const k = splitPoint(n);
  const left = build(hashes, lo, lo + k, paths);
  const right = build(hashes, lo + k, hi, paths);
  for (let i = lo; i < lo + k; i += 1) paths[i].push(right);
  for (let i = lo + k; i < hi; i += 1) paths[i].push(left);
  return nodeHash(left, right);
}

function tree(leafHashes) {
  if (!Array.isArray(leafHashes) || leafHashes.length === 0) throw new Error('a batch needs at least one record');
  if (leafHashes.length > MAX_LEAVES) throw new Error('a batch holds at most ' + MAX_LEAVES + ' records');
  for (const h of leafHashes) bytes32(h, 'a leaf hash');
  const paths = leafHashes.map(() => []);
  const root = build(leafHashes, 0, leafHashes.length, paths);
  return { root, paths };
}

function rootFromPath(leaf, index, size, path) {
  if (!Buffer.isBuffer(leaf) || leaf.length !== 32) return null;
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || size < 1 || size > MAX_LEAVES) return null;
  if (index < 0 || index >= size) return null;
  if (!Array.isArray(path) || path.length > MAX_PATH) return null;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of path) {
    if (!Buffer.isBuffer(p) || p.length !== 32) return null;
    if (sn === 0) return null;
    if ((fn & 1) === 1 || fn === sn) {
      r = nodeHash(p, r);
      while ((fn & 1) === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) return null;
  return r;
}

module.exports = { MAX_LEAVES, MAX_PATH, SALT_BYTES, leafHash, nodeHash, commitment, tree, rootFromPath };
