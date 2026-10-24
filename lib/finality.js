// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const crypto = require('crypto');
const { read, clean, failureCode } = require('./client');
const { decode } = require('./bech32m');
const W = require('./wire');

const HELPER_NAMES = Object.freeze({
  finality: ['verifyFinality', 'verify_finality'],
  event: ['verifyEvent', 'verify_event'],
  decode: ['decodeEvent', 'decode_event'],
  transaction: ['verifyTransaction', 'verify_transaction'],
  chainId: ['chainIdFromName', 'chain_id_from_name'],
  nextRoster: ['verifyNextRoster', 'verify_next_roster'],
});
const REQUIRED = Object.freeze(['finality', 'event', 'decode', 'transaction', 'chainId']);
const KIND_CALL = 1;
const MAX_TX_LEAF = 1 << 18;
const MAX_ADDRESS = 64;
const MAX_PROPOSER = 128;
const MAX_EXTRA = 32;
const MAX_STEPS = 64;
const MAX_ROSTER = 4096;
const ATTEST_PK_BYTES = 1952;
const ROOT_BYTES = 32;
const ROOT_SLOTS_MAX = 1n << 16n;
const U64_MAX = (1n << 64n) - 1n;
const HEX = /^[0-9a-fA-F]*$/;
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
    transaction: pick(sources, HELPER_NAMES.transaction),
    chainId: pick(sources, HELPER_NAMES.chainId),
    nextRoster: pick(sources, HELPER_NAMES.nextRoster),
  };
}

function helpersComplete(helpers) {
  return !!helpers && REQUIRED.every((name) => typeof helpers[name] === 'function');
}

const CHECK = require('./finality-check.json');
const BINDING = new WeakMap();

function bindsGenesis(helpers) {
  if (!helpers || typeof helpers.finality !== 'function') return false;
  if (BINDING.has(helpers.finality)) return BINDING.get(helpers.finality);
  let ok = false;
  try {
    const own = parseJson(helpers.finality(BigInt(CHECK.chainId), CHECK.genesis, CHECK.header, CHECK.certificate, CHECK.roster));
    if (own && String(own.signed_stake) === CHECK.signedStake && String(own.hash).toLowerCase() === CHECK.hash) {
      try {
        helpers.finality(BigInt(CHECK.chainId), CHECK.otherGenesis, CHECK.header, CHECK.certificate, CHECK.roster);
      } catch (e) {
        ok = true;
      }
    }
  } catch (e) {
    ok = false;
  }
  BINDING.set(helpers.finality, ok);
  return ok;
}

function sha3(...parts) {
  const h = crypto.createHash('sha3-256');
  for (const p of parts) h.update(p);
  return h.digest();
}

function hexBytes(value, what, max) {
  if (typeof value !== 'string' || value.length % 2 !== 0 || !HEX.test(value) || (max !== undefined && value.length > max * 2)) throw new Error(what + ' is not hex');
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

function decodeTransaction(bytes) {
  let at = 0;
  const need = (n) => {
    if (at + n > bytes.length) throw new Error('the transaction is truncated');
  };
  const take = (n) => {
    need(n);
    const v = Buffer.from(bytes.subarray(at, at + n));
    at += n;
    return v;
  };
  const u64 = () => take(8).readBigUInt64LE(0);
  const u8 = () => take(1)[0];
  const blob = (max) => {
    const n = u64();
    if (n > BigInt(max)) throw new Error('a transaction field is too long');
    return take(Number(n));
  };
  const sender = blob(MAX_ADDRESS);
  u64();
  u64();
  take(16);
  const target = blob(MAX_ADDRESS);
  const args = blob(MAX_TX_LEAF);
  u64();
  const chainId = u64();
  const asset = blob(32);
  if (asset.length !== 0 && asset.length !== 32) throw new Error('the transaction names a malformed asset');
  u64();
  const kind = u8();
  u8();
  blob(MAX_TX_LEAF);
  if (at !== bytes.length) throw new Error('the transaction has trailing bytes');
  return { sender, target, args, chainId, kind };
}

function callProblems(tx, ctx) {
  const { receipt } = ctx;
  const problems = [];
  const payload = (address) => {
    try {
      return decode(address, 'Q', 32);
    } catch (e) {
      return null;
    }
  };
  const sender = payload(receipt.anchor.sender);
  const target = payload(receipt.contract);
  if (!sender || !tx.sender.equals(sender)) problems.push('it was signed by another account');
  if (!target || !tx.target.equals(target)) problems.push('it calls another contract');
  if (tx.kind !== KIND_CALL) problems.push('it is not a contract call');
  if (tx.chainId !== ctx.chainId) problems.push('it was signed for another chain');
  const carries = ctx.custom ? W.carriesCommitment(tx.args, ctx.anchored) : W.callMatches(tx.args, ctx.anchored, receipt.kind, receipt.until);
  if (!carries) problems.push('it does not carry this commitment');
  return problems;
}

async function proveTransaction(client, who, ctx, header) {
  const { receipt, helpers } = ctx;
  const fetchTx = method(client, ['transactionProof', 'getTransactionProof']);
  if (!fetchTx) return { state: 'unserved', detail: who + ' does not serve transaction inclusion proofs' };
  let reply;
  try {
    reply = await read(() => fetchTx(receipt.anchor.tx));
  } catch (e) {
    return { state: 'unserved', detail: who + ' could not serve a transaction inclusion proof (' + failureCode(e) + ')' };
  }
  const root = header.transactionRoot.toString('hex');
  let leaf;
  let steps;
  try {
    if (!reply || typeof reply !== 'object' || Array.isArray(reply)) throw new Error('no proof was returned');
    if (reply.tx_id !== receipt.anchor.tx) throw new Error('the proof is for another transaction');
    if (reply.height !== receipt.anchor.height) throw new Error('the proof is for another block');
    if (!Number.isSafeInteger(reply.index) || reply.index < 0) throw new Error('the proof names no position');
    if (typeof reply.transaction_root !== 'string' || reply.transaction_root.toLowerCase() !== root) {
      throw new Error('the proof names a transaction root other than the certified one');
    }
    leaf = hexBytes(reply.leaf, 'the transaction leaf', MAX_TX_LEAF);
    steps = parseSteps(reply.steps);
  } catch (e) {
    return { state: 'unproved', detail: 'the transaction proof served by ' + who + ' does not prove the transaction of the receipt under the certified block (' + clean(e.message, 80) + '), so it is set aside' };
  }
  const included = attempt(helpers.transaction, root, receipt.anchor.tx, leaf.toString('hex'), JSON.stringify(steps));
  let local = false;
  try {
    local = decode(receipt.anchor.tx, 'QTX', 32).equals(sha3(leaf)) && includedLocally(Buffer.from(root, 'hex'), leaf, steps);
  } catch (e) {
    local = false;
  }
  if (included.error || included.value !== true || !local) {
    return { state: 'unproved', detail: 'the transaction proof served by ' + who + ' does not prove the transaction of the receipt under the certified block, its path or leaf does not lead to the certified transaction root, so it is set aside' };
  }
  let tx;
  try {
    tx = decodeTransaction(leaf);
  } catch (e) {
    return { state: 'unproved', detail: 'the transaction ' + clean(receipt.anchor.tx, 80) + ' is included under the certified block but could not be read (' + clean(e.message, 80) + '), so it is set aside' };
  }
  const problems = callProblems(tx, ctx);
  if (problems.length > 0) {
    return { state: 'refuted', detail: 'the transaction ' + clean(receipt.anchor.tx, 80) + ' is included under the certified block but ' + problems.join(', ') };
  }
  return { state: 'proven', detail: 'the anchoring transaction is included under it' };
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

function rosterMember(m, ids) {
  if (!m || typeof m !== 'object' || Array.isArray(m)) throw new Error('a validator roster member is malformed');
  if (!Number.isSafeInteger(m.id) || m.id < 0 || ids.has(m.id)) throw new Error('a validator roster member has a missing or repeated id');
  ids.add(m.id);
  if (typeof m.stake !== 'string' || !DIGITS.test(m.stake) || BigInt(m.stake) > U64_MAX) throw new Error('a validator stake is not a whole number');
  if (hexBytes(m.attest_pk, 'an attestation key', ATTEST_PK_BYTES).length !== ATTEST_PK_BYTES) throw new Error('an attestation key is not an ML-DSA-65 public key');
  if (hexBytes(m.root, 'a sortition root', ROOT_BYTES).length !== ROOT_BYTES) throw new Error('a sortition root is not 32 bytes');
  if (typeof m.root_slots !== 'string' || !DIGITS.test(m.root_slots) || BigInt(m.root_slots) < 1n || BigInt(m.root_slots) > ROOT_SLOTS_MAX) {
    throw new Error('the slot count of a sortition root is not a whole number from 1 to ' + ROOT_SLOTS_MAX);
  }
  return { id: m.id, stake: m.stake, attest_pk: m.attest_pk.toLowerCase(), root: m.root.toLowerCase(), root_slots: m.root_slots };
}

function parseRoster(list) {
  if (!Array.isArray(list) || list.length === 0 || list.length > MAX_ROSTER) throw new Error('a validator roster lists no members or too many');
  const ids = new Set();
  const roster = list.map((m) => rosterMember(m, ids));
  if (roster.reduce((sum, m) => sum + BigInt(m.stake), 0n) === 0n) throw new Error('a validator roster carries no stake');
  return roster;
}

function rosterFor(pin, epoch) {
  if (!pin || !pin.rosters || typeof pin.rosters !== 'object') return null;
  const roster = Object.prototype.hasOwnProperty.call(pin.rosters, String(epoch)) ? pin.rosters[String(epoch)] : null;
  if (!Array.isArray(roster) || roster.length === 0) return null;
  try {
    return { roster: parseRoster(roster) };
  } catch (e) {
    return { problem: clean(e.message, 120) };
  }
}

const MAX_ROSTER_WALK = 2048;
const WALKED = new WeakMap();

function walkedKey(ctx, anchor, epoch) {
  return ctx.genesis + '/' + String(ctx.chainId) + '/' + String(ctx.pin.epochBlocks) + '/' + anchor + '/' + epoch;
}

function rosterOfProof(reply, epoch) {
  if (!reply || typeof reply !== 'object' || Array.isArray(reply)) throw new Error('the roster proof is not an object');
  if (reply.epoch !== epoch) throw new Error('the roster proof is for another epoch');
  for (const field of ['header_bytes', 'certificate', 'proof']) {
    if (typeof reply[field] !== 'string' || !/^([0-9a-f]{2})+$/i.test(reply[field])) throw new Error('the roster proof carries no ' + field.replace('_', ' '));
  }
  if (!Array.isArray(reply.members)) throw new Error('the roster proof lists no members');
  return parseRoster(reply.members.map((m) => (m && typeof m === 'object' && !Array.isArray(m) ? Object.assign({}, m, {
    stake: typeof m.stake === 'number' ? String(m.stake) : m.stake,
    root_slots: typeof m.root_slots === 'number' ? String(m.root_slots) : m.root_slots,
  }) : m)));
}

async function walkedRoster(client, ctx, target) {
  const { pin, helpers } = ctx;
  let base = -1;
  for (const key of Object.keys(pin.rosters || {})) {
    const e = Number(key);
    if (Number.isSafeInteger(e) && e < target && e > base && Array.isArray(pin.rosters[key]) && pin.rosters[key].length > 0) base = e;
  }
  if (base < 0) return { unavailable: 'the anchor lies in epoch ' + target + ', whose validator roster this release does not pin, and no earlier epoch is pinned to prove it from' };
  if (typeof helpers.nextRoster !== 'function') return { unavailable: 'the client core cannot check a roster change, so the roster of epoch ' + target + ' cannot be proven from the roster pinned for epoch ' + base };
  const fetchRoster = method(client, ['rosterProof', 'getRosterProof']);
  if (!fetchRoster) return { unavailable: 'the endpoint does not serve roster proofs, so the roster of epoch ' + target + ' cannot be proven from the roster pinned for epoch ' + base };
  const pinned = rosterFor(pin, base);
  if (!pinned || pinned.problem) return { unavailable: 'the roster pinned for epoch ' + base + ' is not usable' };
  const anchor = base + ':' + sha3(Buffer.from(JSON.stringify(pinned.roster))).toString('hex');
  if (!WALKED.has(helpers.nextRoster)) WALKED.set(helpers.nextRoster, new Map());
  const walked = WALKED.get(helpers.nextRoster);
  let start = base;
  let current = pinned.roster;
  for (let e = target; e > base; e -= 1) {
    if (walked.has(walkedKey(ctx, anchor, e))) {
      start = e;
      current = walked.get(walkedKey(ctx, anchor, e));
      break;
    }
  }
  if (target - start > MAX_ROSTER_WALK) return { unavailable: 'the anchor lies ' + (target - start) + ' epochs after the last proven roster, more than the ' + MAX_ROSTER_WALK + ' this release walks' };
  for (let e = start + 1; e <= target; e += 1) {
    let reply;
    try {
      reply = await read(() => fetchRoster(e));
    } catch (e2) {
      return { unavailable: 'the endpoint could not serve the roster proof of epoch ' + e + ' (' + failureCode(e2) + ')' };
    }
    let next;
    try {
      next = rosterOfProof(reply, e);
      const proven = helpers.nextRoster(ctx.chainId, ctx.genesis, BigInt(pin.epochBlocks), BigInt(e - 1), JSON.stringify(current), reply.header_bytes.toLowerCase(), reply.certificate.toLowerCase(), JSON.stringify(next), reply.proof.toLowerCase());
      if (proven !== BigInt(e)) throw new Error('the client core did not confirm the roster of epoch ' + e);
    } catch (e2) {
      return { problem: 'the roster of epoch ' + e + ' could not be proven from the roster of epoch ' + (e - 1) + ' (' + clean(e2 && e2.message, 120) + ')' };
    }
    current = next;
    walked.set(walkedKey(ctx, anchor, e), current);
    while (walked.size > 4096) walked.delete(walked.keys().next().value);
  }
  return { roster: current };
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
    if (!m || typeof m !== 'object' || Array.isArray(m)) throw new Error('a validator set member is malformed');
    if (typeof m.bond_address !== 'string' || m.bond_address.length === 0) throw new Error('a validator set member names no bond address');
    const member = rosterMember(m, ids);
    sum += BigInt(member.stake);
    return member;
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

function pinnedGenesis(net) {
  if (!net || typeof net !== 'object') return null;
  const f = net.finality;
  if (f && typeof f === 'object' && typeof f.genesis === 'string') return f.genesis;
  return typeof net.genesis === 'string' ? net.genesis : null;
}

function certify(ctx, roster, headerHex, certificate) {
  if (typeof certificate !== 'string') return null;
  const checked = attempt(ctx.helpers.finality, ctx.chainId, ctx.genesis, headerHex, certificate.toLowerCase(), JSON.stringify(roster));
  const final = checked.error ? null : parseJson(checked.value);
  if (!final || typeof final !== 'object') return null;
  const elsewhere = attempt(ctx.helpers.finality, ctx.chainId, crypto.randomBytes(32).toString('hex'), headerHex, certificate.toLowerCase(), JSON.stringify(roster));
  if (!elsewhere.error) return null;
  const signed = stake(final.signed_stake);
  const total = stake(final.total_stake);
  const pinnedTotal = roster.reduce((sum, m) => sum + (stake(m.stake) || 0n), 0n);
  const short = signed === null || total === null || total === 0n || total !== pinnedTotal || signed > total || signed * 3n <= total * 2n;
  return Object.assign({}, final, { signed, total, short });
}

async function nodeInfoOf(client, given) {
  if (given && typeof given === 'object' && !Array.isArray(given)) return given;
  const fetchInfo = method(client, ['nodeInfo', 'getNodeInfo']);
  if (!fetchInfo) return null;
  try {
    const info = await read(() => fetchInfo());
    return info && typeof info === 'object' && !Array.isArray(info) ? info : null;
  } catch (e) {
    return null;
  }
}

async function checkpointHolds(who, ctx, fetchFinality) {
  const cp = ctx.pin && ctx.pin.checkpoint;
  if (!cp) return null;
  let reply;
  try {
    reply = await read(() => fetchFinality(cp.height));
  } catch (e) {
    return { state: 'unavailable', detail: who + ' could not serve the header at the pinned checkpoint height ' + cp.height + ' (' + failureCode(e) + '), so the chain it serves could not be tied to the pinned genesis' };
  }
  let bytes;
  try {
    if (!reply || typeof reply !== 'object' || reply.height !== cp.height) throw new Error('the reply is for another height');
    bytes = hexBytes(reply.header_bytes, 'the header', 4096);
    if (decodeHeader(bytes).height !== cp.height) throw new Error('the header is for another height');
  } catch (e) {
    return { state: 'failed', detail: who + ' served a malformed header at the pinned checkpoint height (' + clean(e.message, 80) + ')' };
  }
  const hash = sha3(bytes).toString('hex');
  if (typeof cp.hash === 'string' && cp.hash.length === hash.length && crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(cp.hash))) return null;
  const ep = epochOf(ctx.pin, cp.height);
  const pinned = ep.epoch === undefined ? null : rosterFor(ctx.pin, ep.epoch);
  const final = pinned && pinned.roster ? certify(ctx, pinned.roster, bytes.toString('hex'), reply.certificate) : null;
  if (final && !final.short && String(final.hash).toLowerCase() === hash) {
    return { state: 'refuted', detail: 'validators of the pinned roster certify a block at the checkpoint height ' + cp.height + ' served by ' + who + ' that is not the pinned checkpoint, so that endpoint serves a chain other than the pinned genesis and no proof from it can stand for this receipt' };
  }
  return { state: 'failed', detail: who + ' serves a header at the pinned checkpoint height ' + cp.height + ' other than the pinned one, so the chain it serves is not tied to the pinned genesis and its proof is not used' };
}

async function boundToGenesis(client, who, ctx, fetchFinality) {
  if (!ctx.pin || !ctx.pin.checkpoint) {
    return { state: 'unavailable', detail: 'the network pins no checkpoint, and without one the chain ' + who + ' serves cannot be tied to the pinned genesis, so its proof is not used' };
  }
  const info = await nodeInfoOf(client, ctx.info);
  const served = info && typeof info.genesis_hash === 'string' ? info.genesis_hash.toLowerCase() : null;
  if (served === null) {
    return { state: 'unavailable', detail: who + ' did not name the genesis of the chain it serves, so its proof is not used' };
  }
  if (served !== ctx.genesis || served !== ctx.receipt.chain.genesis || info.chain_id !== ctx.receipt.chain.id) {
    return {
      state: 'failed',
      detail: who + ' names a chain whose genesis is ' + clean(served.slice(0, 16), 16) + ', not the genesis ' +
        ctx.genesis.slice(0, 16) + ' that the receipt and this network name, so its proof is not used',
    };
  }
  return checkpointHolds(who, ctx, fetchFinality);
}

function namesChain(reported, name, helpers) {
  if (reported === name) return true;
  if (typeof reported !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(reported)) return false;
  try {
    return BigInt(reported) === BigInt(helpers.chainId(name));
  } catch (e) {
    return false;
  }
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
    if (!namesChain(fin.chain_id, receipt.chain.id, helpers)) throw new Error('the proof is for another chain');
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
  let pinned = rosterFor(pin, ep.epoch);
  if (!pinned) {
    const walked = await walkedRoster(client, ctx, ep.epoch);
    if (walked.unavailable) return { state: 'unavailable', detail: clean(walked.unavailable, 200) };
    if (walked.problem) return { state: 'failed', detail: clean(walked.problem, 240) };
    pinned = walked;
  }
  if (pinned.problem) {
    return { state: 'unavailable', detail: 'the validator roster pinned for epoch ' + ep.epoch + ' is not used, because ' + pinned.problem + ', and every validator must name its stake, its attestation key and its sortition root with the slot count of that root' };
  }
  const { roster } = pinned;
  const final = certify(ctx, roster, headerHex, fin.certificate);
  if (!final) return { state: 'failed', detail: 'the finality certificate served by ' + who + ' does not verify against the pinned validator roster' };
  const { signed, total } = final;
  if (final.short) {
    return { state: 'failed', detail: 'the finality certificate served by ' + who + ' does not carry more than two thirds of the stake' };
  }
  if (String(final.hash).toLowerCase() !== headerHash || String(final.height) !== String(receipt.anchor.height) ||
    String(final.event_root).toLowerCase() !== header.eventRoot.toString('hex') ||
    String(final.transaction_root).toLowerCase() !== header.transactionRoot.toString('hex')) {
    return { state: 'failed', detail: 'the finality certificate served by ' + who + ' certifies another block' };
  }
  const bound = await boundToGenesis(client, who, ctx, fetchFinality);
  if (bound) return bound;
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
  if (included.error || included.value !== true || !includedLocally(header.eventRoot, leafBytes, steps)) {
    return { state: 'failed', certified, detail: 'the stamp event served by ' + who + ' is not included under the certified block' };
  }
  const certifiedBy = 'a finality certificate from validators holding ' + signed.toString() + ' of ' + total.toString() + ' pinned stake certifies block ' + header.height + ' at time ' + header.time + ', and the stamp event is included under it';
  const tx = await proveTransaction(client, who, ctx, header);
  if (tx.state === 'refuted') return { state: 'refuted', certified, detail: tx.detail };
  return {
    state: 'proven',
    certified,
    selector: String(event.selector).toLowerCase(),
    transaction: tx.state,
    transactionDetail: tx.detail,
    detail: tx.state === 'proven' ? certifiedBy + ', as ' + tx.detail : certifiedBy,
    source: label,
  };
}

async function proveAnchor(ctx) {
  const pin = ctx.net && ctx.net.finality;
  if (!anyPinned(pin)) {
    return { state: 'unavailable', detail: 'no validator roster is pinned for this network yet, so the anchor cannot be proven from finality certificates' };
  }
  const given = ctx.helpers || {};
  const helpers = Object.freeze({ finality: given.finality, event: given.event, decode: given.decode, transaction: given.transaction, chainId: given.chainId, nextRoster: given.nextRoster });
  if (!helpersComplete(helpers)) {
    return { state: 'unavailable', detail: 'this release of the client core cannot check finality certificates and transaction inclusion proofs' };
  }
  if (!bindsGenesis(helpers)) {
    return { state: 'unavailable', detail: 'the finality helpers did not accept a known certificate under its own genesis and refuse it under another, so they do not bind certificates to the genesis and no finality proof is used' };
  }
  const genesis = pinnedGenesis(ctx.net);
  if (typeof genesis !== 'string') {
    return { state: 'unavailable', detail: 'no genesis is pinned for the validator rosters of this network, so a finality proof cannot be bound to the chain of the receipt' };
  }
  if (ctx.receipt.chain.genesis !== genesis || ctx.receipt.chain.id !== ctx.net.chainId) {
    return { state: 'refuted', detail: 'the receipt names a chain or genesis other than the one this network pins its validator rosters for, so no proof from this network can stand for the receipt' };
  }
  let chainId;
  try {
    chainId = BigInt(helpers.chainId(ctx.net.chainId));
  } catch (e) {
    return { state: 'unavailable', detail: 'the numeric chain id could not be derived' };
  }
  const outcomes = [];
  for (const { client, label, info } of ctx.sources) {
    outcomes.push(await proveFrom(client, label, Object.assign({}, ctx, { pin, helpers, chainId, genesis, info })));
  }
  const hashes = [...new Set(outcomes.filter((o) => typeof o.certified === 'string').map((o) => o.certified))];
  if (hashes.length > 1) {
    return {
      state: 'refuted',
      detail: 'verified finality certificates from the pinned roster certify ' + hashes.length + ' different blocks at height ' + ctx.receipt.anchor.height + ', ' + hashes.map((h) => h.slice(0, 16)).join(' and ') + ', so the validators equivocated and the anchor is not accepted',
    };
  }
  const proven = outcomes.find((o) => o.state === 'proven' && o.transaction === 'proven');
  if (proven) return proven;
  const refuted = outcomes.find((o) => o.state === 'refuted');
  if (refuted) return refuted;
  const certifiedOnly = outcomes.find((o) => o.state === 'proven');
  if (certifiedOnly) {
    const bad = outcomes.find((o) => o.state === 'proven' && o.transaction === 'unproved');
    return bad ? Object.assign({}, certifiedOnly, { transaction: 'unproved', transactionDetail: bad.transactionDetail }) : certifiedOnly;
  }
  if (outcomes.length === 0) return { state: 'unavailable', detail: 'no endpoint was available to serve a finality proof' };
  return { state: outcomes.some((o) => o.state === 'failed') ? 'failed' : 'unavailable', detail: outcomes.map((o) => o.detail).join(', ') };
}

module.exports = { bindsGenesis,
  proveAnchor, helpersFrom, helpersComplete, REQUIRED, eventLeaf, decodeHeader, decodeTransaction, parseSteps, pathLength, includedLocally, rosterFromValidatorSet, parseRoster, pinnedGenesis, HELPER_NAMES,
};
