// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { ALGORITHMS } = require('./hash');
const { decode } = require('./bech32m');
const { MAX_LEAVES, MAX_PATH } = require('./merkle');

const FORMAT = 'qstamp-receipt/1';
const HEX32 = /^[0-9a-f]{64}$/;

const KINDS = Object.freeze({
  record: 0,
  file: 1,
  document: 2,
  software_release: 3,
  ai_model: 4,
  ai_dataset: 5,
  ai_agent_action: 6,
  ai_output: 7,
  wallet_binding: 8,
  financial_record: 9,
  public_record: 10,
});

function fail(message) {
  throw new Error('invalid receipt: ' + message);
}

function exactKeys(obj, keys, where) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) fail(where + ' must be an object');
  const got = Object.keys(obj).sort();
  const want = keys.slice().sort();
  if (got.length !== want.length || got.some((k, i) => k !== want[i])) {
    fail(where + ' must hold exactly ' + want.join(', '));
  }
}

function hex32(value, where) {
  if (typeof value !== 'string' || !HEX32.test(value)) fail(where + ' must be 64 lowercase hex characters');
}

function uint(value, where, max) {
  if (!Number.isSafeInteger(value) || value < 0 || (max !== undefined && value > max)) {
    fail(where + ' must be a whole number in range');
  }
}

function identifier(value, hrp, where) {
  try {
    decode(value, hrp, 32);
  } catch (e) {
    fail(where + ' is not a valid ' + hrp + ' identifier');
  }
  if (value !== value.toUpperCase()) fail(where + ' must be upper case');
}

function kindString(value, where) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) || BigInt(value) > (1n << 64n) - 1n) {
    fail(where + ' must be a decimal string that fits in 64 bits');
  }
}

function validate(receipt) {
  exactKeys(receipt, ['format', 'chain', 'contract', 'kind', 'record', 'proof', 'root', 'anchor'], 'the receipt');
  if (receipt.format !== FORMAT) fail('format must be ' + FORMAT);
  exactKeys(receipt.chain, ['id', 'genesis'], 'chain');
  if (typeof receipt.chain.id !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(receipt.chain.id)) fail('chain.id is malformed');
  hex32(receipt.chain.genesis, 'chain.genesis');
  identifier(receipt.contract, 'Q', 'contract');
  kindString(receipt.kind, 'kind');
  exactKeys(receipt.record, ['alg', 'digest', 'salt'], 'record');
  if (!Object.prototype.hasOwnProperty.call(ALGORITHMS, receipt.record.alg)) fail('record.alg is not supported');
  hex32(receipt.record.digest, 'record.digest');
  hex32(receipt.record.salt, 'record.salt');
  exactKeys(receipt.proof, ['index', 'size', 'path'], 'proof');
  uint(receipt.proof.size, 'proof.size', MAX_LEAVES);
  if (receipt.proof.size < 1) fail('proof.size must be at least 1');
  uint(receipt.proof.index, 'proof.index', receipt.proof.size - 1);
  if (!Array.isArray(receipt.proof.path) || receipt.proof.path.length > MAX_PATH) fail('proof.path must be a short list');
  receipt.proof.path.forEach((p, i) => hex32(p, 'proof.path[' + i + ']'));
  hex32(receipt.root, 'root');
  exactKeys(receipt.anchor, ['tx', 'height', 'block', 'time', 'sender'], 'anchor');
  identifier(receipt.anchor.tx, 'QTX', 'anchor.tx');
  uint(receipt.anchor.height, 'anchor.height');
  identifier(receipt.anchor.block, 'QBK', 'anchor.block');
  uint(receipt.anchor.time, 'anchor.time');
  identifier(receipt.anchor.sender, 'Q', 'anchor.sender');
  return receipt;
}

function kindValue(kind) {
  if (typeof kind === 'string' && Object.prototype.hasOwnProperty.call(KINDS, kind)) return String(KINDS[kind]);
  if (typeof kind === 'number' && Number.isSafeInteger(kind) && kind >= 0) return String(kind);
  if (typeof kind === 'bigint' && kind >= 0n && kind < 1n << 64n) return kind.toString();
  if (typeof kind === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(kind) && BigInt(kind) < 1n << 64n) return kind;
  throw new Error('the record kind must be a named kind or a whole number that fits in 64 bits');
}

module.exports = { FORMAT, KINDS, validate, kindValue };
