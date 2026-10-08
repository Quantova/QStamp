// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { addressBytes } = require('./bech32m');

const STAMP_SELECTOR = '6ae4cf77';
const STAMPED_SELECTOR = '5a110849';
const HOST_CONTEXT_BYTES = 120;
const MAX_KIND = (1n << 64n) - 1n;

function kindWord(kind) {
  if (typeof kind !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(kind)) throw new Error('the record kind must be a decimal string');
  const k = BigInt(kind);
  if (k > MAX_KIND) throw new Error('the record kind must fit in 64 bits');
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(k);
  return out;
}

function value32(value) {
  if (!Buffer.isBuffer(value) || value.length !== 32) throw new Error('a stamp commitment is 32 bytes');
  return value;
}

function stampArgs(anchored, kind) {
  return Buffer.concat([
    Buffer.from(STAMP_SELECTOR, 'hex'),
    Buffer.alloc(HOST_CONTEXT_BYTES),
    value32(anchored),
    kindWord(kind),
  ]).toString('hex');
}

function stampedEventData(sender, anchored, kind) {
  return Buffer.concat([addressBytes(sender), value32(anchored), kindWord(kind)]).toString('hex');
}

module.exports = { STAMP_SELECTOR, STAMPED_SELECTOR, kindWord, stampArgs, stampedEventData };
