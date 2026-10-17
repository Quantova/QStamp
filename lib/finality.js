// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const crypto = require('crypto');
const { read, clean, failureCode } = require('./client');
const { decode } = require('./bech32m');

const HELPER_NAMES = Object.freeze({
  finality: ['verifyFinality', 'verify_finality'],
  event: ['verifyEvent', 'verify_event'],
  decode: ['decodeEvent', 'decode_event'],
  chainId: ['chainIdFromName', 'chain_id_from_name'],
});
const MAX_PROPOSER = 128;
const MAX_EXTRA = 32;
const MAX_STEPS = 64;
const MAX_ROSTER = 4096;
const ATTEST_PK_BYTES = 1952;
const U64_MAX = (1n << 64n) - 1n;
const HEX = /^(?:[0-9a-fA-F]{2})*$/;
const DIGITS = /^(0|[1-9][0-9]{0,38})$/;

function pick(sources, names) {
  for (const s of sources) {
    if (!s || (typeof s !== 'object' && typeof s !== 'function')) continue;
    for (const n of names) if (typeof s[n] === 'function') return s[n].bind(s);
  }
  return null;
}

function helpersFrom(mod) {
  const sources = [mod && mod.core, mod];
  return {
    finality: pick(sources, HELPER_NAMES.finality),
    event: pick(sources, HELPER_NAMES.event),
    decode: pick(sources, HELPER_NAMES.decode),
    chainId: pick(sources, HELPER_NAMES.chainId),
  };
}

function sha3(...parts) {
  const h = crypto.createHash('sha3-256');
  for (const p of parts) h.update(p);
  return h.digest();
}

function hexBytes(value, what, max) {
  if (typeof value !== 'string' || !HEX.test(value) || (max !== undefined && value.length > max * 2)) throw new Error(what + ' is not hex');
  return Buffer.from(value, 'hex');
}

function u64le(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
}

function lengthPrefixed(bytes) {
  return Buffer.concat([u64le(bytes.length), bytes]);
}

function eventLeaf(contract, selectorHex, dataHex) {
  return Buffer.concat([
    lengthPrefixed(Buffer.from(contract, 'utf8')),
    lengthPrefixed(Buffer.from(selectorHex, 'hex')),
    lengthPrefixed(Buffer.from(dataHex, 'hex')),
  ]);
}

function decodeHeader(bytes) {
  let at = 0;
  const need = (n) => {
    if (at + n > bytes.length) throw new Error('the header is truncated');
  };
  const u64 = () => {
    need(8);
    const v = bytes.readBigUInt64LE(at);
    at += 8;
    return v;
  };
  const root = () => {
    need(32);
    const v = bytes.subarray(at, at + 32);
    at += 32;
    return Buffer.from(v);
  };
  const blob = (max) => {
    const n = u64();
    if (n > BigInt(max)) throw new Error('a header field is too long');
    need(Number(n));
    const v = bytes.subarray(at, at + Number(n));
    at += Number(n);
    return Buffer.from(v);
  };
  const height = u64();
  const parentHash = root();
  const qRoot = root();
  const transactionRoot = root();
  const eventRoot = root();
  const beaconSeed = root();
  const proposer = blob(MAX_PROPOSER);
  const time = u64();
  const extra = blob(MAX_EXTRA);
  if (at !== bytes.length) throw new Error('the header has trailing bytes');
  if (height > BigInt(Number.MAX_SAFE_INTEGER) || time > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('the header holds a value out of range');
  return { height: Number(height), parentHash, qRoot, transactionRoot, eventRoot, beaconSeed, proposer, time: Number(time), extra };
}

function parseSteps(steps) {
  if (!Array.isArray(steps) || steps.length > MAX_STEPS) throw new Error('the proof steps are not a short list');
  return steps.map((step) => {
    if (!step || typeof step !== 'object') throw new Error('a proof step is malformed');
    const sibling = hexBytes(step.sibling, 'a proof sibling', 32);
    if (sibling.length !== 32) throw new Error('a proof sibling is not 32 bytes');
    const { left } = step;
    if (typeof left !== 'boolean') throw new Error('a proof step does not say which side its sibling is on');
    return { sibling: sibling.toString('hex'), left };
  });
}

function pathLength(count, index) {
  let n = count;
  let i = index;
  let length = 0;
  while (n > 1) {
    let split = 1;
    while (split * 2 < n) split *= 2;
    if (i < split) {
      n = split;
    } else {
      n -= split;
      i -= split;
    }
    length += 1;
  }
  return length;
}

function includedLocally(root, leaf, steps) {
  let acc = sha3(Buffer.from([0x00]), leaf);
  for (const s of steps) {
    const sibling = Buffer.from(s.sibling, 'hex');
    acc = s.left ? sha3(Buffer.from([0x01]), sibling, acc) : sha3(Buffer.from([0x01]), acc, sibling);
  }
  return acc.equals(root);
}

function parseJson(value) {
  if (value && typeof value === 'object') return value;
  if (typeof value !== 'string') return null;
  try {
    return JSON.parse(value);
  } catch (e) {
    return null;
  }
}

function attempt(fn, ...args) {
  try {
    return { value: fn(...args) };
  } catch (e) {
    return { error: e };
  }
}

function method(client, names) {
  for (const n of names) if (client && typeof client[n] === 'function') return client[n].bind(client);
  return null;
}

function stake(value) {
  if (typeof value === 'bigint') return value >= 0n ? value : null;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === 'string' && DIGITS.test(value)) return BigInt(value);
  return null;
}

function rosterFor(pin, epoch) {
  if (!pin || !pin.rosters || typeof pin.rosters !== 'object') return null;
  const roster = Object.prototype.hasOwnProperty.call(pin.rosters, String(epoch)) ? pin.rosters[String(epoch)] : null;
  if (!Array.isArray(roster) || roster.length === 0) return null;
  return roster.map((m) => ({ id: m.id, stake: String(m.stake), attest_pk: String(m.attest_pk) }));
}

function rosterFromValidatorSet(reply, epoch, chainName) {
  if (!reply || typeof reply !== 'object' || Array.isArray(reply)) throw new Error('the validator set is not an object');
  if (reply.epoch !== epoch) throw new Error('the validator set is for another epoch');
  if (typeof chainName !== 'string' || reply.chain_id !== chainName) throw new Error('the validator set is for another chain');
  const members = reply.members;
  if (!Array.isArray(members) || members.length === 0 || members.length > MAX_ROSTER) throw new Error('the validator set lists no members or too many');
  const ids = new Set();
  let sum = 0n;
  const roster = members.map((m) => {
    if (!m || typeof m !== 'object') throw new Error('a validator set member is malformed');
    if (!Number.isSafeInteger(m.id) || m.id < 0 || ids.has(m.id)) throw new Error('a validator set member has a missing or repeated id');
    ids.add(m.id);
    if (typeof m.stake !== 'string' || !DIGITS.test(m.stake) || BigInt(m.stake) > U64_MAX) throw new Error('a validator stake is not a whole number');
    if (typeof m.bond_address !== 'string' || m.bond_address.length === 0) throw new Error('a validator set member names no bond address');
    if (hexBytes(m.attest_pk, 'an attestation key', ATTEST_PK_BYTES).length !== ATTEST_PK_BYTES) throw new Error('an attestation key is not an ML-DSA-65 public key');
    sum += BigInt(m.stake);
    return { id: m.id, stake: m.stake, attest_pk: m.attest_pk.toLowerCase() };
  });
  if (typeof reply.total_stake !== 'string' || !DIGITS.test(reply.total_stake) || BigInt(reply.total_stake) !== sum || sum === 0n) {
    throw new Error('the total stake of the validator set does not add up');
  }
  return roster;
}

function anyPinned(pin) {
  return !!pin && !!pin.rosters && typeof pin.rosters === 'object' && Object.keys(pin.rosters).some((k) => Array.isArray(pin.rosters[k]) && pin.rosters[k].length > 0);
}

function epochOf(pin, height, reported) {
  if (pin && Number.isSafeInteger(pin.epochBlocks) && pin.epochBlocks > 0) {
    const derived = Math.floor(height / pin.epochBlocks);
    if (reported !== undefined && reported !== derived) return { problem: 'the endpoint names epoch ' + reported + ' for a height that lies in epoch ' + derived };
    return { epoch: derived };
  }
  return { unavailable: 'this release pins validator rosters but not the epoch length, so the roster for the anchor height cannot be chosen without trusting the endpoint' };
}

async function proveFrom(client, label, ctx) {
  const { receipt, pin, helpers } = ctx;
  const who = clean(label, 120);
  const fetchFinality = method(client, ['finality', 'getFinality']);
  const fetchProof = method(client, ['eventProof', 'getEventProof']);
  if (!fetchFinality || !fetchProof) return { state: 'unavailable', detail: who + ' does not serve finality proofs' };
  let fin;
  try {
    fin = await read(() => fetchFinality(receipt.anchor.height));
  } catch (e) {
    return { state: 'unavailable', detail: who + ' could not serve a finality proof (' + failureCode(e) + ')' };
  }
  let headerHex;
  let header;
  let headerHash;
  try {
    if (!fin || typeof fin !== 'object') throw new Error('no proof was returned');
    if (fin.height !== receipt.anchor.height) throw new Error('the proof is for another height');
    if (!Number.isSafeInteger(fin.epoch) || fin.epoch < 0) throw new Error('the proof names no epoch');
    if (fin.chain_id !== receipt.chain.id) throw new Error('the proof is for another chain');
    const bytes = hexBytes(fin.header_bytes, 'the header', 4096);
    headerHex = bytes.toString('hex');
    headerHash = sha3(bytes).toString('hex');
    if (typeof fin.header_hash !== 'string' || fin.header_hash.toLowerCase() !== headerHash) throw new Error('the header hash does not match the header');
    header = decodeHeader(bytes);
    if (header.height !== receipt.anchor.height) throw new Error('the header is for another height');
    if (hexBytes(fin.certificate, 'the certificate', 1 << 22).length === 0) throw new Error('the certificate is empty');
  } catch (e) {
    return { state: 'failed', detail: who + ' served a malformed finality proof (' + clean(e.message, 80) + ')' };
  }
  const ep = epochOf(pin, header.height, fin.epoch);
  if (ep.problem) return { state: 'failed', detail: clean(ep.problem, 160) };
  if (ep.unavailable) return { state: 'unavailable', detail: ep.unavailable };
  const roster = rosterFor(pin, ep.epoch);
  if (!roster) {
    return { state: 'unavailable', detail: 'the anchor lies in epoch ' + ep.epoch + ', whose validator roster this release does not pin, and proofs across roster changes are not available yet' };
  }
  const checked = attempt(helpers.finality, ctx.chainId, headerHex, fin.certificate.toLowerCase(), JSON.stringify(roster));
  const final = checked.error ? null : parseJson(checked.value);
  if (!final) return { state: 'failed', detail: 'the finality certificate served by ' + who + ' does not verify against the pinned validator roster' };
  const signed = stake(final.signed_stake);
  const total = stake(final.total_stake);
  const pinnedTotal = roster.reduce((sum, m) => sum + (stake(m.stake) || 0n), 0n);
  if (signed === null || total === null || total === 0n || total !== pinnedTotal || signed > total || signed * 3n < total * 2n) {
    return { state: 'failed', detail: 'the finality certificate served by ' + who + ' carries less than two thirds of the stake' };
  }
  if (String(final.hash).toLowerCase() !== headerHash || String(final.height) !== String(receipt.anchor.height) ||
    String(final.event_root).toLowerCase() !== header.eventRoot.toString('hex')) {
    return { state: 'failed', detail: 'the finality certificate served by ' + who + ' certifies another block' };
  }
  const certified = headerHash;
  let named = null;
  try {
    named = decode(receipt.anchor.block, 'QBK', 32).toString('hex');
  } catch (e) {
    named = null;
  }
  if (named !== headerHash) {
    return { state: 'refuted', certified, detail: 'the certified block at height ' + header.height + ' is not the block named in the receipt' };
  }
  if (String(final.time) !== String(receipt.anchor.time)) {
    return { state: 'refuted', certified, detail: 'the certified block at height ' + header.height + ' has time ' + clean(final.time, 20) + ', not the time in the receipt' };
  }
  if (receipt.until !== undefined && header.time > receipt.until) {
    return { state: 'refuted', certified, detail: 'the certified block is later than the deadline the stamp carries' };
  }
  let index = -1;
  try {
    const listed = await read(() => client.events(receipt.anchor.height));
    const events = listed && Array.isArray(listed.events) ? listed.events : [];
    index = events.findIndex((e) => e && typeof e === 'object' && e.contract === receipt.contract && ctx.selectors.includes(e.selector) &&
      typeof e.data === 'string' && e.data.toLowerCase() === ctx.data);
  } catch (e) {
    index = -1;
  }
  if (index < 0) return { state: 'failed', certified, detail: who + ' did not list the stamp event, so no inclusion proof could be requested' };
  let proof;
  try {
    proof = await read(() => fetchProof(receipt.anchor.height, index));
  } catch (e) {
    return { state: 'unavailable', certified, detail: who + ' could not serve an event inclusion proof (' + failureCode(e) + ')' };
  }
  let leafBytes;
  let steps;
  try {
    if (!proof || typeof proof !== 'object') throw new Error('no proof was returned');
    if (proof.height !== receipt.anchor.height || proof.index !== index) throw new Error('the proof is for another event');
    if (!Number.isSafeInteger(proof.event_count) || proof.event_count <= index) throw new Error('the proof names too few events');
    if (typeof proof.event_root !== 'string' || proof.event_root.toLowerCase() !== header.eventRoot.toString('hex')) {
      throw new Error('the proof names an event root other than the certified one');
    }
    leafBytes = hexBytes(proof.leaf, 'the event leaf', 1 << 16);
    steps = parseSteps(proof.steps);
    if (steps.length !== pathLength(proof.event_count, index)) throw new Error('the proof path does not fit the number of events');
  } catch (e) {
    return { state: 'failed', certified, detail: who + ' served a malformed inclusion proof (' + clean(e.message, 80) + ')' };
  }
  const decoded = attempt(helpers.decode, leafBytes.toString('hex'));
  const event = decoded.error ? null : parseJson(decoded.value);
  const exact = !!event && event.contract === receipt.contract && ctx.selectors.includes(String(event.selector).toLowerCase()) &&
    String(event.data).toLowerCase() === ctx.data && ctx.leaf.some((l) => l.equals(leafBytes));
  if (!exact) return { state: 'failed', certified, detail: 'the event proven by ' + who + ' is not the stamp event of this receipt' };
  const included = attempt(helpers.event, header.eventRoot.toString('hex'), leafBytes.toString('hex'), JSON.stringify(steps));
  if (included.error || included.value !== true) {
    return { state: 'failed', certified, detail: 'the stamp event served by ' + who + ' is not included under the certified block' };
  }
  return {
    state: 'proven',
    certified,
    selector: String(event.selector).toLowerCase(),
    detail: 'a finality certificate from validators holding ' + signed.toString() + ' of ' + total.toString() + ' pinned stake certifies block ' + header.height + ' at time ' + header.time + ', and the stamp event is included under it',
    source: label,
  };
}

async function proveAnchor(ctx) {
  const pin = ctx.net && ctx.net.finality;
  if (!anyPinned(pin)) {
    return { state: 'unavailable', detail: 'no validator roster is pinned for this network yet, so the anchor cannot be proven from finality certificates' };
  }
  const helpers = ctx.helpers || {};
  if (!helpers.finality || !helpers.event || !helpers.decode) {
    return { state: 'unavailable', detail: 'this release of the client core cannot check finality certificates' };
  }
  let chainId;
  try {
    chainId = BigInt(helpers.chainId(ctx.net.chainId));
  } catch (e) {
    return { state: 'unavailable', detail: 'the numeric chain id could not be derived' };
  }
  const outcomes = [];
  for (const { client, label } of ctx.sources) {
    outcomes.push(await proveFrom(client, label, Object.assign({}, ctx, { pin, helpers, chainId })));
  }
  const hashes = [...new Set(outcomes.filter((o) => typeof o.certified === 'string').map((o) => o.certified))];
  if (hashes.length > 1) {
    return {
      state: 'refuted',
      detail: 'verified finality certificates from the pinned roster certify ' + hashes.length + ' different blocks at height ' + ctx.receipt.anchor.height + ', ' + hashes.map((h) => h.slice(0, 16)).join(' and ') + ', so the validators equivocated and the anchor is not accepted',
    };
  }
  const proven = outcomes.find((o) => o.state === 'proven');
  if (proven) return proven;
  const refuted = outcomes.find((o) => o.state === 'refuted');
  if (refuted) return refuted;
  if (outcomes.length === 0) return { state: 'unavailable', detail: 'no endpoint was available to serve a finality proof' };
  return { state: outcomes.some((o) => o.state === 'failed') ? 'failed' : 'unavailable', detail: outcomes.map((o) => o.detail).join(', ') };
}

module.exports = { proveAnchor, helpersFrom, eventLeaf, decodeHeader, parseSteps, pathLength, includedLocally, rosterFromValidatorSet, HELPER_NAMES };
