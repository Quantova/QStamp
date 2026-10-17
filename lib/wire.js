// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { addressBytes } = require('./bech32m');

const STAMP_SELECTOR = '6ae4cf77';
const STAMPED_SELECTOR = '5a110849';
const STAMP_UNTIL_SELECTOR = 'c1c5ac38';
const STAMPED_UNTIL_SELECTOR = '16676021';
const HOST_CONTEXT_BYTES = 120;
const ARGS_OFFSET = 4 + HOST_CONTEXT_BYTES;
const MAX_KIND = (1n << 64n) - 1n;
const MAX_UNTIL = Number.MAX_SAFE_INTEGER;

function kindWord(kind) {
  if (typeof kind !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(kind)) throw new Error('the record kind must be a decimal string');
  const k = BigInt(kind);
  if (k > MAX_KIND) throw new Error('the record kind must fit in 64 bits');
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(k);
  return out;
}

function untilWord(until) {
  if (!Number.isSafeInteger(until) || until < 1 || until > MAX_UNTIL) throw new Error('a stamp deadline is a whole number of seconds since 1970');
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(until));
  return out;
}

function value32(value) {
  if (!Buffer.isBuffer(value) || value.length !== 32) throw new Error('a stamp commitment is 32 bytes');
  return value;
}

function argWords(anchored, kind, until) {
  if (until === undefined) return Buffer.concat([value32(anchored), kindWord(kind)]);
  return Buffer.concat([untilWord(until), value32(anchored), kindWord(kind)]);
}

function stampArgs(anchored, kind, until) {
  return Buffer.concat([
    Buffer.from(until === undefined ? STAMP_SELECTOR : STAMP_UNTIL_SELECTOR, 'hex'),
    Buffer.alloc(HOST_CONTEXT_BYTES),
    argWords(anchored, kind, until),
  ]).toString('hex');
}

function stampedSelector(until) {
  return until === undefined ? STAMPED_SELECTOR : STAMPED_UNTIL_SELECTOR;
}

function stampedEventData(sender, anchored, kind, until) {
  const parts = [addressBytes(sender), value32(anchored), kindWord(kind)];
  if (until !== undefined) parts.push(untilWord(until));
  return Buffer.concat(parts).toString('hex');
}

function callMatches(raw, anchored, kind, until) {
  if (!Buffer.isBuffer(raw)) return false;
  const selector = Buffer.from(until === undefined ? STAMP_SELECTOR : STAMP_UNTIL_SELECTOR, 'hex');
  const words = argWords(anchored, kind, until);
  for (let at = raw.indexOf(selector); at >= 0; at = raw.indexOf(selector, at + 1)) {
    if (raw.length < at + ARGS_OFFSET + words.length) return false;
    if (raw.subarray(at + ARGS_OFFSET, at + ARGS_OFFSET + words.length).equals(words)) return true;
  }
  return false;
}

module.exports = {
  STAMP_SELECTOR, STAMPED_SELECTOR, STAMP_UNTIL_SELECTOR, STAMPED_UNTIL_SELECTOR,
  kindWord, untilWord, stampArgs, stampedSelector, stampedEventData, callMatches,
};
