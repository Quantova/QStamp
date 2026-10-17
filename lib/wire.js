// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { addressBytes } = require('./bech32m');
const OPEN = require('../contract/QStamp.interface.json');
const ISSUER = require('../contract/templates/QStampIssuer.interface.json');
const COUNCIL = require('../contract/templates/QStampCouncil.interface.json');

const MAX_KIND = (1n << 64n) - 1n;
const MAX_UNTIL = Number.MAX_SAFE_INTEGER;
const WIDTHS = Object.freeze({ commitment: 32, hi: 16, lo: 16, kind: 8, until: 8 });

function contractOf(doc, name) {
  const found = doc && Array.isArray(doc.contracts) ? doc.contracts.find((c) => c && c.name === name) : null;
  if (!found || !Array.isArray(found.entries) || !Array.isArray(found.events)) throw new Error('the interface of ' + name + ' is missing');
  return found;
}

function entryOf(contract, name) {
  const entry = contract.entries.find((e) => e && e.name === name);
  if (!entry || !/^[0-9a-f]{8}$/.test(entry.selector) || !Array.isArray(entry.args)) {
    throw new Error('the interface of ' + contract.name + ' has no entry ' + name);
  }
  const args = {};
  let size = 0;
  let context = 0;
  for (const a of entry.args) {
    if (!a || typeof a.key !== 'string' || !Number.isSafeInteger(a.offset) || !Number.isSafeInteger(a.width) || a.offset < 0 || a.width < 1) {
      throw new Error('the interface of ' + contract.name + ' lists a malformed argument');
    }
    args[a.key] = { offset: a.offset, width: a.width };
    size = Math.max(size, a.offset + a.width);
    if (a.key.startsWith('@')) context = Math.max(context, a.offset + a.width);
  }
  return { selector: entry.selector, args, size, context };
}

function eventOf(contract, name) {
  const event = contract.events.find((e) => e && e.name === name);
  if (!event || !/^[0-9a-f]{8}$/.test(event.selector)) throw new Error('the interface of ' + contract.name + ' has no event ' + name);
  return event.selector;
}

function layout(contract, name, roles) {
  const entry = entryOf(contract, name);
  const at = {};
  for (const [role, key] of Object.entries(roles)) {
    const arg = entry.args[key];
    if (!arg || arg.width !== WIDTHS[role]) throw new Error('the entry ' + name + ' of ' + contract.name + ' does not carry ' + key + ' with width ' + WIDTHS[role]);
    if (arg.offset < entry.context) throw new Error('the entry ' + name + ' of ' + contract.name + ' places ' + key + ' inside the host context');
    at[role] = arg.offset;
  }
  return Object.freeze({ contract: contract.name, entry: name, selector: entry.selector, size: entry.size, context: entry.context, at: Object.freeze(at) });
}

const open = contractOf(OPEN, 'QStamp');
const issuer = contractOf(ISSUER, 'QStampIssuer');
const council = contractOf(COUNCIL, 'QStampCouncil');

const LAYOUTS = Object.freeze({
  stamp: layout(open, 'stamp', { hi: 'hi', lo: 'lo', kind: 'kind' }),
  stampUntil: layout(open, 'stamp_until', { hi: 'hi', lo: 'lo', kind: 'kind', until: 'until' }),
  issuerStamp: layout(issuer, 'stamp', { commitment: 'order.commitment' }),
  councilStamp: layout(council, 'stamp', { hi: 'order.hi', lo: 'order.lo' }),
});
const CUSTOM_LAYOUTS = Object.freeze([LAYOUTS.issuerStamp, LAYOUTS.councilStamp]);

const STAMP_SELECTOR = LAYOUTS.stamp.selector;
const STAMP_UNTIL_SELECTOR = LAYOUTS.stampUntil.selector;
const STAMPED_SELECTOR = eventOf(open, 'Stamped');
const STAMPED_UNTIL_SELECTOR = eventOf(open, 'StampedUntil');
const COMMITMENT_STAMPED_SELECTOR = eventOf(issuer, 'Stamped');
const HOST_CONTEXT_BYTES = LAYOUTS.stamp.context;

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

function openLayout(until) {
  return until === undefined ? LAYOUTS.stamp : LAYOUTS.stampUntil;
}

function placed(where, anchored, kind, until) {
  const value = {
    commitment: () => value32(anchored),
    hi: () => value32(anchored).subarray(0, 16),
    lo: () => value32(anchored).subarray(16, 32),
    kind: () => kindWord(kind),
    until: () => untilWord(until),
  };
  return Object.entries(where.at).map(([role, offset]) => [offset, value[role]()]);
}

function stampArgs(anchored, kind, until) {
  const where = openLayout(until);
  const body = Buffer.alloc(where.size);
  for (const [offset, bytes] of placed(where, anchored, kind, until)) bytes.copy(body, offset);
  return Buffer.concat([Buffer.from(where.selector, 'hex'), body]).toString('hex');
}

function stampedSelector(until) {
  return until === undefined ? STAMPED_SELECTOR : STAMPED_UNTIL_SELECTOR;
}

function stampedEventData(sender, anchored, kind, until) {
  const parts = [addressBytes(sender), value32(anchored), kindWord(kind)];
  if (until !== undefined) parts.push(untilWord(until));
  return Buffer.concat(parts).toString('hex');
}

function occurs(raw, where, parts) {
  const selector = Buffer.from(where.selector, 'hex');
  for (let at = raw.indexOf(selector); at >= 0; at = raw.indexOf(selector, at + 1)) {
    const base = at + selector.length;
    if (raw.length < base + where.size) return false;
    if (parts.every(([offset, bytes]) => raw.subarray(base + offset, base + offset + bytes.length).equals(bytes))) return true;
  }
  return false;
}

function callMatches(raw, anchored, kind, until) {
  if (!Buffer.isBuffer(raw)) return false;
  const where = openLayout(until);
  return occurs(raw, where, placed(where, anchored, kind, until));
}

function carriesCommitment(raw, anchored) {
  if (!Buffer.isBuffer(raw)) return false;
  const value = value32(anchored);
  const known = CUSTOM_LAYOUTS.filter((where) => raw.includes(Buffer.from(where.selector, 'hex')));
  if (known.length > 0) return known.some((where) => occurs(raw, where, placed(where, value)));
  const from = 4 + HOST_CONTEXT_BYTES;
  return raw.length >= from + 32 && raw.indexOf(value, from) >= 0;
}

module.exports = {
  STAMP_SELECTOR, STAMPED_SELECTOR, STAMP_UNTIL_SELECTOR, STAMPED_UNTIL_SELECTOR, COMMITMENT_STAMPED_SELECTOR, HOST_CONTEXT_BYTES, LAYOUTS,
  kindWord, untilWord, stampArgs, stampedSelector, stampedEventData, callMatches, carriesCommitment,
};
