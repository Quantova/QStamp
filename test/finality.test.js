// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const qcore = require('@quantovainc/qcore');
const qstamp = require('..');
const wire = require('../lib/wire');
const { verifyWith } = require('../lib/verify');
const F = require('../lib/finality');
const { reader } = require('../lib/transport');
const E = require('../lib/endpoints');
const { checkNetwork } = require('../lib/networks');
const { makeChain, client, gateway, SEED, testNetwork, encode, sha3, headerBytes, merkleRoot, merkleSteps } = require('./chain');

const ML_DSA_65_PK_BYTES = 1952;

const CHAIN_ID = 7741n;
const ROSTER = [
  { id: 1, stake: '40', attest_pk: 'a1'.repeat(16) },
  { id: 2, stake: '30', attest_pk: 'b2'.repeat(16) },
  { id: 3, stake: '30', attest_pk: 'c3'.repeat(16) },
];
const OUTSIDER = 'ee'.repeat(16);

function sign(pk, hash, chainId) {
  return sha3(Buffer.from('stub'), Buffer.from(pk, 'hex'), Buffer.from(hash, 'hex'), Buffer.from(String(chainId))).toString('hex');
}

function certificate(ids, pkOf) {
  return (height, hash) => Buffer.from(JSON.stringify({
    height,
    hash,
    sigs: Object.fromEntries(ids.map((id) => [id, sign(pkOf ? pkOf(id) : ROSTER.find((m) => m.id === id).attest_pk, hash, CHAIN_ID)])),
  })).toString('hex');
}

function decodeLeaf(hex) {
  const b = Buffer.from(hex, 'hex');
  let at = 0;
  const take = () => {
    const n = Number(b.readBigUInt64LE(at));
    at += 8;
    const v = b.subarray(at, at + n);
    at += n;
    return v;
  };
  const contract = take().toString('utf8');
  const selector = take().toString('hex');
  const data = take().toString('hex');
  if (at !== b.length) throw new Error('the event leaf is malformed');
  return JSON.stringify({ contract, selector, data });
}

const stubHelpers = {
  finality(chainId, headerHex, certHex, rosterJson) {
    const roster = JSON.parse(rosterJson);
    const bytes = Buffer.from(headerHex, 'hex');
    const header = F.decodeHeader(bytes);
    const hash = sha3(bytes).toString('hex');
    const cert = JSON.parse(Buffer.from(certHex, 'hex').toString('utf8'));
    if (cert.hash !== hash || cert.height !== header.height) throw new Error('the certificate does not name this header');
    let signed = 0n;
    let total = 0n;
    for (const m of roster) total += BigInt(m.stake);
    for (const [id, sig] of Object.entries(cert.sigs)) {
      const member = roster.find((m) => String(m.id) === id);
      if (!member) throw new Error('an attestation comes from a validator outside the roster');
      if (sig !== sign(member.attest_pk, hash, chainId)) throw new Error('an attestation signature does not verify');
      signed += BigInt(member.stake);
    }
    if (signed * 3n < total * 2n) throw new Error('the attesting validators hold less than two thirds of the stake');
    return JSON.stringify({
      height: String(header.height), hash, event_root: header.eventRoot.toString('hex'), time: String(header.time),
      signed_stake: String(signed), total_stake: String(total),
    });
  },
  event(rootHex, leafHex, stepsJson) {
    return F.includedLocally(Buffer.from(rootHex, 'hex'), Buffer.from(leafHex, 'hex'), JSON.parse(stepsJson));
  },
  decode: decodeLeaf,
  chainId: () => CHAIN_ID,
};

const pinned = testNetwork({ finality: { epochBlocks: 2 ** 40, rosters: { 0: ROSTER } } });

async function stamped(chain, record) {
  const [receipt] = await qstamp.stamp({
    seed: SEED,
    index: 0,
    records: [{ digest: qstamp.digestBytes(record) }],
    kind: 'document',
    clients: [client(chain, 'https://alpha.example'), client(chain, 'https://beta.example')],
    timeoutMs: 1000,
  });
  return receipt;
}

function only(chain, extra) {
  return [client(chain, 'https://prover.example', Object.assign({ proofs: true }, extra || {}))];
}

test('a finality certificate over the pinned roster proves a receipt even when every endpoint is untrusted', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a proven record');
  const receipt = await stamped(chain, record);
  const r = await verifyWith(pinned, receipt, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(r.status, 'valid');
  assert.strictEqual(r.trust, 'finality-proof');
  assert.strictEqual(qstamp.isProven(r), true);
  assert.match(r.checks.find((c) => c.name === 'finality').detail, /100 of 100 pinned stake/);
});

test('a finality or inclusion reply that departs from the gateway shape is refused', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a strictly parsed record');
  const receipt = await stamped(chain, record);
  const fin = (change) => ({ finality: (c, h) => change(c.finalityAt(Number(h))) });
  const inc = (change) => ({ eventProof: (c, h, i) => change(c.eventProofAt(Number(h), Number(i))) });
  const drop = (key) => (reply) => {
    const copy = Object.assign({}, reply);
    delete copy[key];
    return copy;
  };
  const variants = [
    [fin((f) => Object.assign(drop('header_bytes')(f), { header: f.header_bytes })), /malformed finality proof \(the header is not hex\)/],
    [fin(drop('header_hash')), /the header hash does not match the header/],
    [fin((f) => Object.assign(f, { header_hash: '00'.repeat(32) })), /the header hash does not match the header/],
    [fin(drop('chain_id')), /the proof is for another chain/],
    [fin((f) => Object.assign(f, { chain_id: 'Q-main-net-1' })), /the proof is for another chain/],
    [fin(drop('epoch')), /the proof names no epoch/],
    [fin((f) => Object.assign(f, { height: String(f.height) })), /the proof is for another height/],
    [fin((f) => Object.assign(f, { certificate: '' })), /the certificate is empty/],
    [inc((p) => Object.assign(drop('steps')(p), { path: p.steps })), /proof steps are not a short list/],
    [inc((p) => Object.assign(p, { steps: [{ sibling: '22'.repeat(32), sibling_on_left: true }] })), /does not say which side/],
    [inc(drop('event_count')), /names too few events/],
    [inc((p) => Object.assign(p, { index: p.index + 1 })), /the proof is for another event/],
    [inc(drop('event_root')), /event root other than the certified one/],
    [inc((p) => Object.assign(p, { steps: [{ sibling: '22'.repeat(32), left: true }] })), /does not fit the number of events/],
  ];
  for (const [override, pattern] of variants) {
    const r = await verifyWith(pinned, receipt, { bytes: record, clients: only(chain, override), trustCustomEndpoints: true }, { helpers: stubHelpers });
    assert.strictEqual(r.status, 'unproven', String(pattern));
    assert.ok(r.notices.some((n) => pattern.test(n)), String(pattern) + ' ' + JSON.stringify(r.notices));
  }
});

test('the corrected gateway replies are served and read through the guarded transport', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('read over http');
  const receipt = await stamped(chain, record);
  const key = (b) => b.repeat(ML_DSA_65_PK_BYTES);
  chain.roster = [
    { id: 1, stake: '40', bond_address: receipt.anchor.sender, attest_pk: key('a1') },
    { id: 2, stake: '60', bond_address: receipt.anchor.sender, attest_pk: key('b2') },
  ];
  const gw = await gateway(chain, { proofs: true });
  try {
    const r = reader(gw.url, () => true);
    const fin = await r.finality(receipt.anchor.height);
    assert.deepStrictEqual(Object.keys(fin).sort(), ['certificate', 'chain_id', 'epoch', 'header_bytes', 'header_hash', 'height']);
    const proof = await r.eventProof(receipt.anchor.height, 0);
    assert.deepStrictEqual(Object.keys(proof).sort(), ['event_count', 'event_root', 'height', 'index', 'leaf', 'steps']);
    const set = await r.validatorSet(chain.epoch);
    assert.deepStrictEqual(Object.keys(set).sort(), ['chain_id', 'epoch', 'members', 'total_stake']);
    assert.deepStrictEqual(F.rosterFromValidatorSet(set, chain.epoch, chain.chainId), chain.roster.map((m) => ({ id: m.id, stake: m.stake, attest_pk: m.attest_pk })));
    await assert.rejects(r.validatorSet(chain.epoch + 1), (e) => e.code === 'QSTAMP_TRANSPORT' && e.reason === 'http 404');
  } finally {
    await gw.close();
  }
});

test('a validator set is accepted only for the asked epoch and chain with a consistent total', () => {
  const pk = 'c3'.repeat(ML_DSA_65_PK_BYTES);
  const good = { epoch: 3, chain_id: 'Q-test-net-1', total_stake: '70', members: [{ id: 1, stake: '30', bond_address: 'Q1X', attest_pk: pk }, { id: 2, stake: '40', bond_address: 'Q1Y', attest_pk: pk }] };
  assert.strictEqual(F.rosterFromValidatorSet(good, 3, 'Q-test-net-1').length, 2);
  const bad = [
    [Object.assign({}, good, { epoch: 2 }), 3, /another epoch/],
    [good, 3, /another chain/, 'Q-main-net-1'],
    [Object.assign({}, good, { total_stake: '71' }), 3, /does not add up/],
    [Object.assign({}, good, { total_stake: 70 }), 3, /does not add up/],
    [Object.assign({}, good, { members: [] }), 3, /no members/],
    [Object.assign({}, good, { members: [good.members[0], good.members[0]] }), 3, /repeated id/],
    [Object.assign({}, good, { members: [Object.assign({}, good.members[0], { stake: 30 })] }), 3, /not a whole number/],
    [Object.assign({}, good, { members: [Object.assign({}, good.members[0], { attest_pk: 'c3'.repeat(32) })] }), 3, /not an ML-DSA-65 public key/],
    [Object.assign({}, good, { members: [Object.assign({}, good.members[0], { bond_address: '' })] }), 3, /no bond address/],
  ];
  for (const [reply, epoch, pattern, name] of bad) {
    assert.throws(() => F.rosterFromValidatorSet(reply, epoch, name || 'Q-test-net-1'), pattern);
  }
});

test('the event proofs of the fake gateway verify with the published client core helpers', () => {
  const helpers = F.helpersFrom(qcore);
  assert.ok(helpers.finality && helpers.event && helpers.decode, 'the client core provides the proof helpers');
  const chain = makeChain();
  const contract = chain.contract;
  for (let i = 0; i < 5; i += 1) chain.events.get(chain.height).push({ contract, selector: wire.STAMPED_SELECTOR, data: String(i).padStart(2, '0').repeat(72) });
  for (let i = 0; i < 5; i += 1) {
    const p = chain.eventProofAt(chain.height, i);
    assert.strictEqual(p.steps.length, F.pathLength(p.event_count, i));
    assert.strictEqual(helpers.event(p.event_root, p.leaf, JSON.stringify(p.steps)), true);
    assert.strictEqual(helpers.event(p.event_root, p.leaf, JSON.stringify(p.steps.map((s) => Object.assign({}, s, { left: !s.left })))), false);
    assert.deepStrictEqual(JSON.parse(helpers.decode(p.leaf)), JSON.parse(decodeLeaf(p.leaf)));
  }
});

test('a proven anchor stays valid when another endpoint denies it', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2]);
  const record = Buffer.from('a disputed record');
  const receipt = await stamped(chain, record);
  const denier = client(chain, 'https://denier.example', { events: () => ({ events: [] }) });
  const r = await verifyWith(pinned, receipt, { bytes: record, clients: [denier].concat(only(chain)), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(r.status, 'valid');
  assert.ok(r.notices.some((n) => /no matching stamp event/.test(n)));
  assert.ok(r.checks.every((c) => c.ok));
});

test('a certificate from keys outside the pinned roster does not prove a fabricated anchor', async () => {
  const chain = makeChain();
  const net = qstamp.NETWORKS.testnet;
  const record = Buffer.from('never anchored');
  const sender = qcore.core.address(new Uint8Array(32).fill(0x66), 0);
  const prepared = qstamp.prepare([{ digest: qstamp.digestBytes(record) }]);
  const kind = '0';
  const anchored = qstamp.commitment(prepared.root, 1, { genesis: net.genesis, contract: net.contract, sender, kind });
  const time = chain.time - 100;
  const height = chain.height - 400;
  const data = wire.stampedEventData(sender, anchored, kind);
  const leaf = F.eventLeaf(net.contract, wire.STAMPED_SELECTOR, data);
  const root = merkleRoot([sha3(Buffer.from([0]), leaf)]);
  const bytes = headerBytes(height, time, root);
  const hash = sha3(bytes).toString('hex');
  const forgedCert = Buffer.from(JSON.stringify({ height, hash, sigs: { 9: sign(OUTSIDER, hash, CHAIN_ID) } })).toString('hex');
  const stolenIds = Buffer.from(JSON.stringify({ height, hash, sigs: { 1: sign(OUTSIDER, hash, CHAIN_ID), 2: sign(OUTSIDER, hash, CHAIN_ID) } })).toString('hex');
  const r0 = prepared.recs[0];
  const receipt = {
    format: qstamp.RECEIPT_FORMAT,
    chain: { id: net.chainId, genesis: net.genesis },
    contract: net.contract,
    kind,
    record: { alg: r0.alg, digest: r0.digest.toString('hex'), salt: r0.salt.toString('hex') },
    proof: { index: 0, size: 1, path: [] },
    root: prepared.root.toString('hex'),
    anchor: { tx: encode('QTX', crypto.randomBytes(32)), height, block: encode('QBK', crypto.randomBytes(32)), time, sender },
  };
  for (const cert of [forgedCert, stolenIds]) {
    const liar = {
      base: 'https://liar.example',
      nodeInfo: async () => ({ chain_id: net.chainId, genesis_hash: net.genesis, head_height: height + 10 }),
      transaction: async () => ({ status: 'finalised', height, block: receipt.anchor.block, from: sender, to: net.contract, kind: 'call', raw: wire.stampArgs(anchored, kind) }),
      events: async () => ({ events: [{ contract: net.contract, selector: wire.STAMPED_SELECTOR, data }] }),
      block: async () => ({ block: receipt.anchor.block, height, time }),
      finality: async () => ({ height, epoch: 0, chain_id: net.chainId, header_bytes: bytes.toString('hex'), header_hash: hash, certificate: cert }),
      eventProof: async () => ({ height, index: 0, event_count: 1, event_root: root.toString('hex'), leaf: leaf.toString('hex'), steps: [] }),
    };
    const r = await verifyWith(pinned, receipt, { bytes: record, clients: [liar], trustCustomEndpoints: true }, { helpers: stubHelpers });
    assert.strictEqual(r.status, 'unproven');
    assert.ok(r.notices.some((n) => /does not verify against the pinned validator roster/.test(n)));
  }
});

test('less than two thirds of the stake never proves an anchor, even when a helper returns without error', async () => {
  const chain = makeChain();
  chain.certify = certificate([2, 3]);
  const record = Buffer.from('a thin quorum');
  const receipt = await stamped(chain, record);
  const opts = { bytes: record, clients: only(chain), trustCustomEndpoints: true };
  const strict = await verifyWith(pinned, receipt, opts, { helpers: stubHelpers });
  assert.strictEqual(strict.status, 'unproven');
  const lax = Object.assign({}, stubHelpers, {
    finality(chainId, headerHex, certHex) {
      const bytes = Buffer.from(headerHex, 'hex');
      const header = F.decodeHeader(bytes);
      return JSON.stringify({ height: String(header.height), hash: sha3(bytes).toString('hex'), event_root: header.eventRoot.toString('hex'), time: String(header.time), signed_stake: '60', total_stake: '100' });
    },
  });
  const r = await verifyWith(pinned, receipt, opts, { helpers: lax });
  assert.strictEqual(r.status, 'unproven');
  assert.ok(r.notices.some((n) => /less than two thirds/.test(n)));
  const inflated = Object.assign({}, stubHelpers, {
    finality(chainId, headerHex, certHex) {
      const bytes = Buffer.from(headerHex, 'hex');
      const header = F.decodeHeader(bytes);
      return JSON.stringify({ height: String(header.height), hash: sha3(bytes).toString('hex'), event_root: header.eventRoot.toString('hex'), time: String(header.time), signed_stake: '60', total_stake: '90' });
    },
  });
  const shrunk = await verifyWith(pinned, receipt, opts, { helpers: inflated });
  assert.strictEqual(shrunk.status, 'unproven');
});

test('signatures from exactly two thirds of the stake prove an anchor, as the chain accepts', async () => {
  const thirds = [
    { id: 1, stake: '10', attest_pk: 'a1'.repeat(16) },
    { id: 2, stake: '10', attest_pk: 'b2'.repeat(16) },
    { id: 3, stake: '10', attest_pk: 'c3'.repeat(16) },
  ];
  const net = testNetwork({ finality: { epochBlocks: 2 ** 40, rosters: { 0: thirds } } });
  const chain = makeChain();
  chain.certify = certificate([1, 2], (id) => thirds.find((m) => m.id === id).attest_pk);
  const record = Buffer.from('exactly two thirds');
  const receipt = await stamped(chain, record);
  const r = await verifyWith(net, receipt, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(r.status, 'valid');
  assert.strictEqual(r.trust, 'finality-proof');
  assert.match(r.checks.find((c) => c.name === 'finality').detail, /20 of 30 pinned stake/);
  chain.certify = certificate([1], (id) => thirds.find((m) => m.id === id).attest_pk);
  const lone = Buffer.from('one third');
  const fewer = await stamped(chain, lone);
  const r2 = await verifyWith(net, fewer, { bytes: lone, clients: only(chain), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(r2.status, 'unproven');
});

test('an anchor in an epoch whose roster is not pinned stays unproven', async () => {
  const chain = makeChain({ epoch: 0 });
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a later epoch');
  const receipt = await stamped(chain, record);
  const later = testNetwork({ finality: { epochBlocks: 2 ** 40, rosters: { 4: ROSTER } } });
  const r = await verifyWith(later, receipt, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(r.status, 'unproven');
  assert.match(r.checks.find((c) => c.name === 'proof').detail, /epoch 0, whose validator roster this release does not pin/);
});

test('pinned rosters without a pinned epoch length never let an endpoint choose the roster', async () => {
  const chain = makeChain({ epoch: 0 });
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('an endpoint chosen epoch');
  const receipt = await stamped(chain, record);
  const loose = testNetwork({ finality: { epochBlocks: null, rosters: { 0: ROSTER } } });
  const r = await verifyWith(loose, receipt, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(r.status, 'unproven');
  assert.match(r.checks.find((c) => c.name === 'proof').detail, /not the epoch length/);
});

test('a proven anchor binds the block named in the receipt and needs its transaction confirmed', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a bound block');
  const receipt = await stamped(chain, record);
  const opts = { bytes: record, clients: only(chain), trustCustomEndpoints: true };
  const otherBlock = JSON.parse(JSON.stringify(receipt));
  otherBlock.anchor.block = chain.blocks.get(receipt.anchor.height - 1).block;
  const moved = await verifyWith(pinned, otherBlock, opts, { helpers: stubHelpers });
  assert.strictEqual(moved.status, 'invalid');
  const otherTx = JSON.parse(JSON.stringify(receipt));
  otherTx.anchor.tx = encode('QTX', crypto.randomBytes(32));
  const unknown = await verifyWith(pinned, otherTx, opts, { helpers: stubHelpers });
  assert.strictEqual(unknown.status, 'indeterminate');
  assert.strictEqual(qstamp.isProven(unknown), false);
  assert.match(unknown.trustDetail, /the transaction id in the receipt is not covered by the proof until the gateway serves a transaction inclusion proof/);
});

test('two verified certificates for different blocks at the anchor height refute the anchor in either order', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('an equivocation');
  const receipt = await stamped(chain, record);
  const fork = only(chain, {
    finality: (c, h) => {
      const real = c.finalityAt(Number(h));
      const header = F.decodeHeader(Buffer.from(real.header_bytes, 'hex'));
      const bytes = headerBytes(header.height, header.time + 50, header.eventRoot);
      const hash = sha3(bytes).toString('hex');
      return Object.assign({}, real, { header_bytes: bytes.toString('hex'), header_hash: hash, certificate: certificate([1, 2, 3])(header.height, hash) });
    },
  });
  fork[0].base = 'https://fork.example';
  for (const clients of [fork.concat(only(chain)), only(chain).concat(fork)]) {
    const r = await verifyWith(pinned, receipt, { bytes: record, clients, trustCustomEndpoints: true }, { helpers: stubHelpers });
    assert.strictEqual(r.status, 'invalid');
    assert.strictEqual(qstamp.isProven(r), false);
    assert.match(r.checks.find((c) => c.name === 'finality').detail, /2 different blocks at height .* equivocated/);
  }
  const alone = await verifyWith(pinned, receipt, { bytes: record, clients: only(chain).concat([client(chain, 'https://second.example', { proofs: true })]), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(alone.status, 'valid');
});

test('an epoch derived from the height overrides the one an endpoint names', async () => {
  const chain = makeChain({ epoch: 0 });
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a derived epoch');
  const receipt = await stamped(chain, record);
  const byHeight = testNetwork({ finality: { epochBlocks: 1000, rosters: { 0: ROSTER } } });
  const r = await verifyWith(byHeight, receipt, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(r.status, 'unproven');
  assert.ok(r.notices.some((n) => /names epoch 0 for a height that lies in epoch/.test(n)));
});

test('a client core without the proof helpers leaves the anchor unproven', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('no helper');
  const receipt = await stamped(chain, record);
  const current = F.helpersFrom(qcore);
  const r = await verifyWith(pinned, receipt, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: current.finality ? {} : current });
  assert.strictEqual(r.status, 'unproven');
  assert.match(r.checks.find((c) => c.name === 'proof').detail, /cannot check finality certificates/);
});

test('a certified block whose time differs from the receipt makes the receipt invalid', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a moved clock');
  const receipt = await stamped(chain, record);
  const shifted = only(chain, { block: (c, h) => Object.assign({}, c.blocks.get(Number(h)), { time: c.blocks.get(Number(h)).time - 50 }) });
  const forged = JSON.parse(JSON.stringify(receipt));
  forged.anchor.time -= 50;
  const r = await verifyWith(pinned, forged, { bytes: record, clients: shifted, trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(r.status, 'invalid');
  assert.match(r.checks.find((c) => c.name === 'finality').detail, /not the time in the receipt/);
});

test('an inclusion proof for another event, another root or a broken path does not prove the stamp', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a swapped leaf');
  const receipt = await stamped(chain, record);
  const other = F.eventLeaf(receipt.contract, wire.STAMPED_SELECTOR, '00'.repeat(72));
  const variants = [
    [{ eventProof: (c, h, i) => Object.assign(c.eventProofAt(Number(h), Number(i)), { leaf: other.toString('hex') }) }, /not the stamp event of this receipt/],
    [{ eventProof: (c, h, i) => Object.assign(c.eventProofAt(Number(h), Number(i)), { event_root: '11'.repeat(32) }) }, /event root other than the certified one/],
    [{ eventProof: (c, h, i) => Object.assign(c.eventProofAt(Number(h), Number(i)), { event_count: 2, steps: [{ sibling: '22'.repeat(32), left: true }] }) }, /not included under the certified block/],
  ];
  for (const [override, pattern] of variants) {
    const r = await verifyWith(pinned, receipt, { bytes: record, clients: only(chain, override), trustCustomEndpoints: true }, { helpers: stubHelpers });
    assert.strictEqual(r.status, 'unproven');
    assert.ok(r.notices.some((n) => pattern.test(n)), String(pattern));
  }
});

test('no finality request is made while no roster is pinned', async () => {
  const chain = makeChain();
  const record = Buffer.from('no pin yet');
  const receipt = await stamped(chain, record);
  let asked = 0;
  const watcher = only(chain, { finality: () => { asked += 1; return null; } });
  const r = await qstamp.verify(receipt, { bytes: record, clients: watcher, trustCustomEndpoints: true });
  assert.strictEqual(r.status, 'unproven');
  assert.strictEqual(asked, 0);
  assert.match(r.checks.find((c) => c.name === 'proof').detail, /no validator roster is pinned/);
});

test('the proof helpers are detected on the client core under their published names', () => {
  const f = () => true;
  const found = F.helpersFrom({ core: { verifyFinality: f, verifyEvent: f, decodeEvent: f, chainIdFromName: f } });
  assert.ok(found.finality && found.event && found.decode && found.chainId);
  const snake = F.helpersFrom({ verify_finality: f, verify_event: f, decode_event: f });
  assert.ok(snake.finality && snake.event && snake.decode);
  const today = F.helpersFrom(qcore);
  assert.ok(today.chainId && today.finality && today.event && today.decode);
  assert.strictEqual(require('@quantovainc/qcore/package.json').version, require('../package.json').dependencies['@quantovainc/qcore']);
  for (const name of ['verifyFinality', 'verifyEvent', 'decodeEvent', 'chainIdFromName']) assert.strictEqual(typeof qcore.core[name], 'function', name);
});

test('proof steps decode from the gateway form and reject a wrong root', () => {
  const leaves = ['a', 'b', 'c', 'd', 'e'].map((x) => Buffer.from(x));
  const hashed = leaves.map((l) => sha3(Buffer.from([0]), l));
  const root = merkleRoot(hashed);
  const steps = F.parseSteps(merkleSteps(hashed, 3));
  assert.ok(F.includedLocally(root, leaves[3], steps));
  assert.ok(!F.includedLocally(root, leaves[2], steps));
  assert.ok(!F.includedLocally(Buffer.alloc(32), leaves[3], steps));
  assert.throws(() => F.parseSteps([{ sibling: '00', left: true }]));
  assert.throws(() => F.parseSteps([{ sibling: '00'.repeat(32) }]));
  assert.throws(() => F.parseSteps(new Array(65).fill({ sibling: '00'.repeat(32), left: false })));
  assert.throws(() => F.parseSteps([{ sibling: '00'.repeat(32), sibling_on_left: false }]));
  assert.deepStrictEqual([[1, 0], [2, 1], [3, 0], [3, 2], [5, 4], [8, 7]].map(([n, i]) => F.pathLength(n, i)), [0, 1, 2, 1, 1, 3]);
});

test('a header with trailing or oversized fields is refused', () => {
  const good = headerBytes(9, 100, Buffer.alloc(32));
  assert.strictEqual(F.decodeHeader(good).height, 9);
  assert.throws(() => F.decodeHeader(Buffer.concat([good, Buffer.from([0])])), /trailing/);
  assert.throws(() => F.decodeHeader(good.subarray(0, 40)), /truncated/);
});

async function officialPair(t, chain, extra) {
  const one = await gateway(chain, extra);
  const two = await gateway(chain, Object.assign({ host: '::1' }, extra || {}));
  t.after(() => Promise.all([one.close(), two.close()]));
  return [{ url: one.url, operator: 'Operator One' }, { url: two.url, operator: 'Operator Two' }];
}

test('on a network that pins rosters an official quorum without a finality proof is never valid', async (t) => {
  const chain = makeChain();
  const record = Buffer.from('a defence build');
  const receipt = await stamped(chain, record);
  const rpcs = await officialPair(t, chain);
  const strict = testNetwork({ rpcs, finality: { epochBlocks: 2 ** 40, rosters: { 0: ROSTER } } });
  const r = await verifyWith(strict, receipt, { bytes: record, allowLoopback: true }, { helpers: stubHelpers });
  assert.strictEqual(r.status, 'unproven');
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.trust, 'none');
  assert.strictEqual(qstamp.isProven(r), false);
  assert.match(r.checks.find((c) => c.name === 'proof').detail, /only through a finality proof/);
  const asked = testNetwork({ rpcs, requireFinality: true });
  const required = await verifyWith(asked, receipt, { bytes: record, allowLoopback: true }, { helpers: stubHelpers });
  assert.strictEqual(required.status, 'unproven');
  assert.strictEqual(qstamp.isProven(required), false);
  const waived = testNetwork({ rpcs, requireFinality: false, finality: { epochBlocks: 2 ** 40, rosters: { 0: ROSTER } } });
  const quorum = await verifyWith(waived, receipt, { bytes: record, allowLoopback: true }, { helpers: stubHelpers });
  assert.strictEqual(quorum.status, 'valid');
  assert.strictEqual(quorum.trust, 'official-quorum');
});

test('on a network that pins rosters a finality proof from its official endpoints is still valid', async (t) => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a proven defence build');
  const receipt = await stamped(chain, record);
  const rpcs = await officialPair(t, chain, { proofs: true });
  const strict = testNetwork({ rpcs, finality: { epochBlocks: 2 ** 40, rosters: { 0: ROSTER } } });
  const r = await verifyWith(strict, receipt, { bytes: record, allowLoopback: true }, { helpers: stubHelpers });
  assert.strictEqual(r.status, 'valid');
  assert.strictEqual(r.trust, 'finality-proof');
  assert.strictEqual(qstamp.isProven(r), true);
  chain.certify = certificate([1, 2, 3], () => OUTSIDER);
  const bad = await verifyWith(strict, receipt, { bytes: record, allowLoopback: true }, { helpers: stubHelpers });
  assert.strictEqual(bad.status, 'indeterminate');
  assert.strictEqual(qstamp.isProven(bad), false);
});

test('plain http endpoints of a network are refused unless on loopback with allowLoopback or marked insecure', async () => {
  const one = (entry) => testNetwork({ rpcs: [Object.assign({ operator: 'Operator One' }, entry)] });
  assert.throws(() => checkNetwork(one({ url: 'http://203.0.113.5:8645' })), /plain http/);
  assert.throws(() => checkNetwork(one({ url: 'http://node.sovereign.example:8645' }), { allowLoopback: true }), /plain http/);
  assert.throws(() => checkNetwork(one({ url: 'http://127.0.0.1:8645' })), /allowLoopback/);
  assert.strictEqual(checkNetwork(one({ url: 'http://127.0.0.1:8645' }), { allowLoopback: true }).rpcs.length, 1);
  assert.strictEqual(checkNetwork(one({ url: 'http://203.0.113.5:8645', insecure: true })).rpcs.length, 1);
  assert.throws(() => checkNetwork(one({ url: 'http://203.0.113.5:8645', insecure: 1 })), /left out or set to true/);
  assert.throws(() => checkNetwork(one({ url: 'https://203.0.113.5', insecure: true })), /only to a network endpoint reached over plain http/);
  assert.throws(() => checkNetwork(one({ url: 'http://203.0.113.5:8645', insecure: true, ca: 'x' })), /plain http/);
  assert.throws(() => checkNetwork(one({ url: 'https://203.0.113.5', cacert: 'x' })), /only url, operator, ca, cert, key and insecure/);
  assert.throws(() => checkNetwork(one({ url: 'https://203.0.113.5', cert: 'x' })), /together/);
  assert.throws(() => checkNetwork(testNetwork({ requireFinality: 'yes' })), /either true or false/);
  const plan = await E.endpointsFor({}, one({ url: 'http://203.0.113.5:8645' }), 'verify').catch((e) => e);
  assert.match(plan.message, /plain http/);
  const sovereign = one({ url: 'http://192.0.2.10:8645', insecure: true });
  const entry = E.describe('http://192.0.2.10:8645', sovereign);
  assert.strictEqual(entry.official, true);
  assert.strictEqual(entry.tls.insecure, true);
  await assert.rejects(reader('http://192.0.2.10:8645', () => false, entry.tls).nodeInfo(), (e) => e.reason === 'address refused');
  await assert.rejects(reader('http://192.0.2.10:8645', () => false, null).nodeInfo(), (e) => e.reason === 'plaintext http refused');
  assert.strictEqual(E.describe({ url: 'http://192.0.2.10:8645' }, testNetwork()).tls, null);
});
