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
const { commitment, leafHash, tree } = require('../lib/merkle');
const { kindValue } = require('../lib/receipt');
const { makeChain, client, gateway, SEED, testNetwork, encode, sha3, headerBytes, wrapperBytes, merkleRoot, merkleSteps, checkpointOf, checkpointReply } = require('./chain');

const ML_DSA_65_PK_BYTES = 1952;

const CHAIN_ID = BigInt(qcore.core.chainIdFromName(qstamp.NETWORKS.testnet.chainId));
const rootOf = (id) => sha3(Buffer.from('sortition root of validator ' + id)).toString('hex');
const member = (id, stake, b) => ({ id, stake, attest_pk: b.repeat(ML_DSA_65_PK_BYTES), root: rootOf(id), root_slots: '64' });
const ROSTER = [member(1, '40', 'a1'), member(2, '30', 'b2'), member(3, '30', 'c3')];
const OUTSIDER = 'ee'.repeat(ML_DSA_65_PK_BYTES);

function sign(pk, hash, chainId, genesis) {
  return sha3(Buffer.from('stub'), Buffer.from(pk, 'hex'), Buffer.from(hash, 'hex'), Buffer.from(String(chainId)), Buffer.from(genesis, 'hex')).toString('hex');
}

function certificate(ids, pkOf, credentialOf, genesis) {
  return (height, hash) => Buffer.from(JSON.stringify({
    height,
    hash,
    sigs: Object.fromEntries(ids.map((id) => [id, sign(pkOf ? pkOf(id) : ROSTER.find((m) => m.id === id).attest_pk, hash, CHAIN_ID, genesis || qstamp.NETWORKS.testnet.genesis)])),
    credentials: Object.fromEntries(ids.map((id) => [id, credentialOf ? credentialOf(id) : rootOf(id)])),
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
  const tx = at < b.length ? take().toString('utf8') : '';
  if (at !== b.length) throw new Error('the event leaf is malformed');
  return JSON.stringify({ contract, selector, data, tx });
}

const CHECK = require('../lib/finality-check.json');
const realFinality = (...args) => qcore.core.verifyFinality(...args);
const throughCheck = (fn) => function finality(chainId, genesis, headerHex, certHex, rosterJson) {
  if (headerHex === CHECK.header) return realFinality(chainId, genesis, headerHex, certHex, rosterJson);
  return fn(chainId, genesis, headerHex, certHex, rosterJson);
};

const stubHelpers = {
  finality: throughCheck((chainId, genesis, headerHex, certHex, rosterJson) => {
    if (typeof genesis !== 'string' || !/^[0-9a-f]{64}$/.test(genesis)) throw new Error('the genesis hash is 64 lowercase hexadecimal characters');
    const roster = JSON.parse(rosterJson);
    const bytes = Buffer.from(headerHex, 'hex');
    const header = F.decodeHeader(bytes);
    const hash = sha3(bytes).toString('hex');
    const cert = JSON.parse(Buffer.from(certHex, 'hex').toString('utf8'));
    if (cert.hash !== hash || cert.height !== header.height) throw new Error('the certificate does not name this header');
    let signed = 0n;
    let total = 0n;
    for (const m of roster) {
      if (typeof m.root !== 'string' || !/^[0-9a-f]{64}$/.test(m.root)) throw new Error('a roster member needs its sortition root');
      if (typeof m.root_slots !== 'string' || !/^[1-9][0-9]*$/.test(m.root_slots)) throw new Error('a roster member needs root_slots as a digit string');
      total += BigInt(m.stake);
    }
    for (const [id, sig] of Object.entries(cert.sigs)) {
      const signer = roster.find((m) => String(m.id) === id);
      if (!signer) throw new Error('an attestation comes from a validator outside the roster');
      if (sig !== sign(signer.attest_pk, hash, chainId, genesis)) throw new Error('an attestation signature does not verify');
      if (!cert.credentials || cert.credentials[id] !== signer.root) throw new Error('an attestation does not prove its committee membership');
      signed += BigInt(signer.stake);
    }
    if (signed * 3n < total * 2n) throw new Error('the attesting validators hold less than two thirds of the stake');
    return JSON.stringify({
      height: String(header.height), hash, event_root: header.eventRoot.toString('hex'), transaction_root: header.transactionRoot.toString('hex'), time: String(header.time),
      signed_stake: String(signed), total_stake: String(total),
    });
  }),
  event(rootHex, leafHex, stepsJson) {
    return F.includedLocally(Buffer.from(rootHex, 'hex'), Buffer.from(leafHex, 'hex'), JSON.parse(stepsJson));
  },
  transaction(rootHex, txId, leafHex, stepsJson) {
    const leaf = Buffer.from(leafHex, 'hex');
    return encode('QTX', sha3(leaf)) === txId && F.includedLocally(Buffer.from(rootHex, 'hex'), leaf, JSON.parse(stepsJson));
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
  chain.roster = [
    Object.assign(member(1, '40', 'a1'), { bond_address: receipt.anchor.sender }),
    Object.assign(member(2, '60', 'b2'), { bond_address: receipt.anchor.sender, root: rootOf(2).toUpperCase(), root_slots: '65536' }),
  ];
  const gw = await gateway(chain, { proofs: true });
  try {
    const r = reader(gw.url, () => true);
    const fin = await r.finality(receipt.anchor.height);
    assert.deepStrictEqual(Object.keys(fin).sort(), ['certificate', 'chain_id', 'epoch', 'header_bytes', 'header_hash', 'height']);
    const proof = await r.eventProof(receipt.anchor.height, 0);
    assert.deepStrictEqual(Object.keys(proof).sort(), ['event_count', 'event_root', 'height', 'index', 'leaf', 'steps']);
    const txProof = await r.transactionProof(receipt.anchor.tx);
    assert.deepStrictEqual(Object.keys(txProof).sort(), ['height', 'index', 'leaf', 'steps', 'transaction_root', 'tx_id']);
    assert.strictEqual(txProof.tx_id, receipt.anchor.tx);
    assert.strictEqual(txProof.transaction_root, F.decodeHeader(Buffer.from(fin.header_bytes, 'hex')).transactionRoot.toString('hex'));
    await assert.rejects(r.transactionProof(encode('QTX', crypto.randomBytes(32))), (e) => e.code === 'QSTAMP_TRANSPORT' && e.reason === 'http 404');
    const set = await r.validatorSet(chain.epoch);
    assert.deepStrictEqual(Object.keys(set).sort(), ['chain_id', 'epoch', 'members', 'total_stake']);
    assert.deepStrictEqual(Object.keys(set.members[0]).sort(), ['attest_pk', 'bond_address', 'id', 'root', 'root_slots', 'stake']);
    assert.deepStrictEqual(F.rosterFromValidatorSet(set, chain.epoch, chain.chainId), chain.roster.map((m) => ({ id: m.id, stake: m.stake, attest_pk: m.attest_pk, root: m.root.toLowerCase(), root_slots: m.root_slots })));
    await assert.rejects(r.validatorSet(chain.epoch + 1), (e) => e.code === 'QSTAMP_TRANSPORT' && e.reason === 'http 404');
  } finally {
    await gw.close();
  }
});

test('a validator set is accepted only for the asked epoch and chain with a consistent total', () => {
  const pk = 'c3'.repeat(ML_DSA_65_PK_BYTES);
  const good = {
    epoch: 3,
    chain_id: 'Q-test-net-01',
    total_stake: '70',
    members: [
      { id: 1, stake: '30', bond_address: 'Q1X', attest_pk: pk, root: rootOf(1), root_slots: '64' },
      { id: 2, stake: '40', bond_address: 'Q1Y', attest_pk: pk, root: rootOf(2), root_slots: '1' },
    ],
  };
  assert.deepStrictEqual(F.rosterFromValidatorSet(good, 3, 'Q-test-net-01').map((m) => [m.root, m.root_slots]), [[rootOf(1), '64'], [rootOf(2), '1']]);
  const first = (change) => Object.assign({}, good, { members: [Object.assign({}, good.members[0], change), good.members[1]] });
  const without = (key) => {
    const m = Object.assign({}, good.members[0]);
    delete m[key];
    return Object.assign({}, good, { members: [m, good.members[1]] });
  };
  const bad = [
    [Object.assign({}, good, { epoch: 2 }), 3, /another epoch/],
    [good, 3, /another chain/, 'Q-main-net-1'],
    [Object.assign({}, good, { total_stake: '71' }), 3, /does not add up/],
    [Object.assign({}, good, { total_stake: 70 }), 3, /does not add up/],
    [Object.assign({}, good, { members: [] }), 3, /no members/],
    [Object.assign({}, good, { members: [good.members[0], good.members[0]] }), 3, /repeated id/],
    [Object.assign({}, good, { members: [Object.assign({}, good.members[0], { stake: 30 })] }), 3, /not a whole number/],
    [Object.assign({}, good, { members: [Object.assign({}, good.members[0], { attest_pk: 'c3'.repeat(32) })] }), 3, /not an ML-DSA-65 or ML-DSA-87 public key/],
    [Object.assign({}, good, { members: [Object.assign({}, good.members[0], { bond_address: '' })] }), 3, /no bond address/],
    [without('root'), 3, /a sortition root is not hex/],
    [without('root_slots'), 3, /slot count of a sortition root/],
    [first({ root: rootOf(1).slice(2) }), 3, /a sortition root is not 32 bytes/],
    [first({ root: rootOf(1) + '00' }), 3, /a sortition root is not hex/],
    [first({ root: 'zz' + rootOf(1).slice(2) }), 3, /a sortition root is not hex/],
    [first({ root: Buffer.from(rootOf(1), 'hex') }), 3, /a sortition root is not hex/],
    [first({ root_slots: 64 }), 3, /slot count of a sortition root/],
    [first({ root_slots: '0' }), 3, /from 1 to 65536/],
    [first({ root_slots: '65537' }), 3, /from 1 to 65536/],
    [first({ root_slots: '064' }), 3, /slot count of a sortition root/],
    [first({ root_slots: '-1' }), 3, /slot count of a sortition root/],
    [first({ root_slots: '18446744073709551616' }), 3, /from 1 to 65536/],
  ];
  for (const [reply, epoch, pattern, name] of bad) {
    assert.throws(() => F.rosterFromValidatorSet(reply, epoch, name || 'Q-test-net-01'), pattern);
  }
});

test('the pinned roster hands every sortition root to the client core and a roster without them is refused', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a roster with roots');
  const receipt = await stamped(chain, record);
  const seen = [];
  const watching = Object.assign({}, stubHelpers, {
    finality(chainId, genesis, headerHex, certHex, rosterJson) {
      if (headerHex !== CHECK.header && genesis === qstamp.NETWORKS.testnet.genesis) seen.push(JSON.parse(rosterJson));
      return stubHelpers.finality(chainId, genesis, headerHex, certHex, rosterJson);
    },
  });
  const r = await verifyWith(pinned, receipt, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: watching });
  assert.strictEqual(r.status, 'valid');
  assert.deepStrictEqual(seen, [ROSTER.map((m) => ({ id: m.id, stake: m.stake, attest_pk: m.attest_pk, root: m.root, root_slots: m.root_slots }))]);
  const drop = (key) => ROSTER.map((m, i) => {
    const copy = Object.assign({}, m);
    if (i === 1) delete copy[key];
    return copy;
  });
  const change = (field) => ROSTER.map((m, i) => (i === 1 ? Object.assign({}, m, field) : m));
  const refused = [
    [drop('root'), /a sortition root is not hex/],
    [drop('root_slots'), /slot count of a sortition root/],
    [change({ root: rootOf(2).slice(0, 62) }), /a sortition root is not 32 bytes/],
    [change({ root_slots: 64 }), /slot count of a sortition root/],
    [change({ root_slots: '65537' }), /from 1 to 65536/],
    [change({ attest_pk: 'b2'.repeat(16) }), /not an ML-DSA-65 or ML-DSA-87 public key/],
    [change({ attest_pk: 'b2'.repeat(2592) }), /mixes ML-DSA-65 and ML-DSA-87/],
    [change({ stake: 30 }), /not a whole number/],
    [change({ id: 1 }), /repeated id/],
  ];
  for (const [roster, pattern] of refused) {
    const net = testNetwork({ finality: { epochBlocks: 2 ** 40, rosters: { 0: roster } } });
    assert.throws(() => checkNetwork(net), (e) => /the network roster of epoch 0 is refused/.test(e.message) && pattern.test(e.message), String(pattern));
    const v = await verifyWith(net, receipt, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: watching });
    assert.strictEqual(v.status, 'indeterminate', String(pattern));
    assert.strictEqual(qstamp.isProven(v), false, String(pattern));
    assert.ok(v.checks.some((c) => c.name === 'network' && !c.ok && pattern.test(c.detail)), String(pattern));
    const direct = await F.proveAnchor({ net: { chainId: pinned.chainId, genesis: pinned.genesis, finality: { epochBlocks: 2 ** 40, rosters: { 0: roster } } }, helpers: watching, sources: only(chain).map((client) => ({ client, label: client.base })), receipt });
    assert.strictEqual(direct.state, 'unavailable', String(pattern));
    assert.match(direct.detail, /the validator roster pinned for epoch 0 is not used, because/);
    assert.match(direct.detail, pattern);
  }
  assert.strictEqual(seen.length, 1);
  for (const rosters of [{ x: ROSTER }, { '01': ROSTER }, { 0: {} }]) {
    assert.throws(() => checkNetwork(testNetwork({ finality: { epochBlocks: 2 ** 40, rosters } })), /keyed by whole epoch numbers|not a list of validators/);
  }
  assert.strictEqual(checkNetwork(testNetwork({ finality: { epochBlocks: 2 ** 40, rosters: { 0: [] } } })).finality.rosters[0].length, 0);
  assert.strictEqual(checkNetwork(pinned), pinned);
});

test('a pinned root that does not open the credential of a signer never proves a receipt', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a credential for another root');
  const receipt = await stamped(chain, record);
  const opts = { bytes: record, clients: only(chain), trustCustomEndpoints: true };
  const wrong = testNetwork({ finality: { epochBlocks: 2 ** 40, rosters: { 0: ROSTER.map((m, i) => (i === 0 ? Object.assign({}, m, { root: rootOf(9) }) : m)) } } });
  const r = await verifyWith(wrong, receipt, opts, { helpers: stubHelpers });
  assert.strictEqual(r.status, 'unproven');
  assert.strictEqual(qstamp.isProven(r), false);
  assert.ok(r.notices.some((n) => /does not verify against the pinned validator roster/.test(n)));
  chain.certify = certificate([1, 2, 3], null, (id) => (id === 2 ? rootOf(1) : rootOf(id)));
  const tampered = await stamped(chain, Buffer.from('a tampered credential'));
  const t = await verifyWith(pinned, tampered, { bytes: Buffer.from('a tampered credential'), clients: only(chain), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(t.status, 'unproven');
  assert.strictEqual(qstamp.isProven(t), false);
});

test('the event and transaction proofs of the fake gateway verify with the published client core helpers', async () => {
  const helpers = F.helpersFrom(qcore);
  assert.ok(F.helpersComplete(helpers), 'the client core provides the proof helpers');
  const stampChain = makeChain();
  const receipt = await stamped(stampChain, Buffer.from('a transaction for the client core'));
  const t = stampChain.transactionProofAt(receipt.anchor.tx);
  assert.strictEqual(helpers.transaction(t.transaction_root, t.tx_id, t.leaf, JSON.stringify(t.steps)), true);
  assert.strictEqual(helpers.transaction(t.transaction_root, encode('QTX', crypto.randomBytes(32)), t.leaf, JSON.stringify(t.steps)), false);
  assert.strictEqual(helpers.transaction('11'.repeat(32), t.tx_id, t.leaf, JSON.stringify(t.steps)), false);
  const decoded = F.decodeTransaction(Buffer.from(t.leaf, 'hex'));
  assert.strictEqual(decoded.args.toString('hex'), stampChain.txs.get(receipt.anchor.tx).raw);
  assert.strictEqual(decoded.chainId, CHAIN_ID);
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
  const forgedCert = Buffer.from(JSON.stringify({ height, hash, sigs: { 9: sign(OUTSIDER, hash, CHAIN_ID, net.genesis) } })).toString('hex');
  const stolenIds = Buffer.from(JSON.stringify({ height, hash, sigs: { 1: sign(OUTSIDER, hash, CHAIN_ID, net.genesis), 2: sign(OUTSIDER, hash, CHAIN_ID, net.genesis) } })).toString('hex');
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
    finality: throughCheck((chainId, genesis, headerHex) => {
      if (genesis !== qstamp.NETWORKS.testnet.genesis) throw new Error('the certificate does not verify under this genesis');
      const bytes = Buffer.from(headerHex, 'hex');
      const header = F.decodeHeader(bytes);
      return JSON.stringify({ height: String(header.height), hash: sha3(bytes).toString('hex'), event_root: header.eventRoot.toString('hex'), time: String(header.time), signed_stake: '60', total_stake: '100' });
    }),
  });
  const r = await verifyWith(pinned, receipt, opts, { helpers: lax });
  assert.strictEqual(r.status, 'unproven');
  assert.ok(r.notices.some((n) => /does not carry more than two thirds/.test(n)));
  const inflated = Object.assign({}, stubHelpers, {
    finality: throughCheck((chainId, genesis, headerHex) => {
      if (genesis !== qstamp.NETWORKS.testnet.genesis) throw new Error('the certificate does not verify under this genesis');
      const bytes = Buffer.from(headerHex, 'hex');
      const header = F.decodeHeader(bytes);
      return JSON.stringify({ height: String(header.height), hash: sha3(bytes).toString('hex'), event_root: header.eventRoot.toString('hex'), time: String(header.time), signed_stake: '60', total_stake: '90' });
    }),
  });
  const shrunk = await verifyWith(pinned, receipt, opts, { helpers: inflated });
  assert.strictEqual(shrunk.status, 'unproven');
});

test('signatures from exactly two thirds of the stake leave an anchor unproven, more than two thirds prove it', async () => {
  const thirds = [member(1, '10', 'a1'), member(2, '10', 'b2'), member(3, '10', 'c3')];
  const net = testNetwork({ finality: { epochBlocks: 2 ** 40, rosters: { 0: thirds } } });
  const chain = makeChain();
  chain.certify = certificate([1, 2], (id) => thirds.find((m) => m.id === id).attest_pk);
  const record = Buffer.from('exactly two thirds');
  const receipt = await stamped(chain, record);
  const r = await verifyWith(net, receipt, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(r.status, 'unproven');
  assert.ok(r.notices.some((n) => /does not carry more than two thirds/.test(n)), JSON.stringify(r.notices));
  chain.certify = certificate([1, 2, 3], (id) => thirds.find((m) => m.id === id).attest_pk);
  const all = Buffer.from('every validator');
  const full = await stamped(chain, all);
  const rf = await verifyWith(net, full, { bytes: all, clients: only(chain), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(rf.status, 'valid');
  assert.strictEqual(rf.trust, 'finality-proof');
  assert.match(rf.checks.find((c) => c.name === 'finality').detail, /30 of 30 pinned stake/);
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

test('a proven anchor binds the block and the transaction named in the receipt', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a bound block');
  const receipt = await stamped(chain, record);
  const elsewhere = await stamped(chain, Buffer.from('another record'));
  const opts = { bytes: record, clients: only(chain), trustCustomEndpoints: true };
  const proven = await verifyWith(pinned, receipt, opts, { helpers: stubHelpers });
  assert.strictEqual(proven.status, 'valid');
  assert.match(proven.checks.find((c) => c.name === 'finality').detail, /the anchoring transaction is included under it/);
  const otherBlock = JSON.parse(JSON.stringify(receipt));
  otherBlock.anchor.block = chain.blocks.get(receipt.anchor.height - 1).block;
  const moved = await verifyWith(pinned, otherBlock, opts, { helpers: stubHelpers });
  assert.strictEqual(moved.status, 'invalid');
  const otherTx = JSON.parse(JSON.stringify(receipt));
  otherTx.anchor.tx = elsewhere.anchor.tx;
  const swapped = await verifyWith(pinned, otherTx, opts, { helpers: stubHelpers });
  assert.strictEqual(swapped.status, 'indeterminate');
  assert.strictEqual(qstamp.isProven(swapped), false);
  assert.match(swapped.trustDetail, /does not prove the transaction of the receipt under the certified block \(the proof is for another block\)/);
  const randomTx = JSON.parse(JSON.stringify(receipt));
  randomTx.anchor.tx = encode('QTX', crypto.randomBytes(32));
  const unknown = await verifyWith(pinned, randomTx, opts, { helpers: stubHelpers });
  assert.strictEqual(unknown.status, 'indeterminate');
  assert.strictEqual(qstamp.isProven(unknown), false);
  assert.match(unknown.trustDetail, /could not serve a transaction inclusion proof .* so the transaction id in the receipt is not covered by the proof/);
});

test('a proven transaction keeps a receipt valid whatever other endpoints say about it', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a transaction proven by inclusion');
  const receipt = await stamped(chain, record);
  const deny = (tx) => ({ transaction: (c, id) => Object.assign({}, c.txs.get(id), tx) });
  const cases = [
    only(chain, { transaction: () => ({ status: 'unknown' }) }),
    only(chain, deny({ from: qcore.core.address(new Uint8Array(32).fill(0x55), 0) })),
    [client(chain, 'https://denier.example', deny({ raw: '00' }))].concat(only(chain, { transaction: () => ({ status: 'unknown' }) })),
    [client(chain, 'https://lagging.example', { nodeInfo: (c) => ({ chain_id: c.chainId, genesis_hash: c.genesis, head_height: receipt.anchor.height - 1 }) })].concat(only(chain)),
  ];
  for (const clients of cases) {
    const r = await verifyWith(pinned, receipt, { bytes: record, clients, trustCustomEndpoints: true }, { helpers: stubHelpers });
    assert.strictEqual(r.status, 'valid', JSON.stringify(r.checks));
    assert.strictEqual(r.trust, 'finality-proof');
    assert.strictEqual(qstamp.isProven(r), true);
    assert.ok(r.checks.every((c) => c.ok));
    assert.ok(r.notices.some((n) => /^(transaction|chain)/.test(n)), JSON.stringify(r.notices));
  }
});

test('without transaction proofs from the gateway the transaction must be confirmed by an endpoint', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('an older gateway');
  const receipt = await stamped(chain, record);
  const older = (extra) => only(chain, Object.assign({ noTransactionProofs: true }, extra || {}));
  const confirmed = await verifyWith(pinned, receipt, { bytes: record, clients: older(), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(confirmed.status, 'valid');
  assert.ok(confirmed.checks.some((c) => c.ok && c.name === 'transaction'));
  const unconfirmed = await verifyWith(pinned, receipt, { bytes: record, clients: older({ transaction: () => { throw new Error('the endpoint is unreachable'); } }), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(unconfirmed.status, 'indeterminate');
  assert.strictEqual(qstamp.isProven(unconfirmed), false);
  assert.match(unconfirmed.trustDetail, /does not serve transaction inclusion proofs, so the transaction id in the receipt is not covered by the proof, and no endpoint confirmed the transaction/);
  assert.ok(unconfirmed.checks.some((c) => !c.ok && c.transport && c.name === 'transaction'));
  assert.ok(unconfirmed.checks.every((c) => c.ok || c.transport));
  for (const transaction of [(c, id) => Object.assign({}, c.txs.get(id), { raw: '00' }), () => ({ status: 'unknown' })]) {
    const disputed = await verifyWith(pinned, receipt, { bytes: record, clients: older({ transaction }), trustCustomEndpoints: true }, { helpers: stubHelpers });
    assert.strictEqual(disputed.status, 'indeterminate');
    assert.strictEqual(qstamp.isProven(disputed), false);
    assert.match(disputed.trustDetail, /an endpoint reported that the transaction does not match/);
  }
});

test('a transaction proof for another transaction, another root or a broken path never proves a receipt and never refutes it', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a swapped transaction');
  const receipt = await stamped(chain, record);
  const h = receipt.anchor.height;
  const at = (c) => c.transactionProofAt(receipt.anchor.tx);
  const forged = (change) => ({ transactionProof: (c) => change(at(c), c) });
  const sibling = (c, args, extra) => {
    const leaf = wrapperBytes(Object.assign({ from: receipt.anchor.sender, to: receipt.contract, args, nonce: 999, chainId: c.numericChainId }, extra || {}));
    return { leaf, id: encode('QTX', sha3(leaf)) };
  };
  const pair = (c, leafB) => {
    const leaves = [Buffer.from(at(c).leaf, 'hex'), leafB].map((l) => sha3(Buffer.from([0]), l));
    return { root: merkleRoot(leaves).toString('hex'), steps: merkleSteps(leaves, 0) };
  };
  const variants = [
    [forged((p) => Object.assign(p, { tx_id: encode('QTX', crypto.randomBytes(32)) })), /the proof is for another transaction/],
    [forged((p) => Object.assign(p, { height: h + 1 })), /the proof is for another block/],
    [forged((p) => Object.assign(p, { transaction_root: '11'.repeat(32) })), /transaction root other than the certified one/],
    [forged((p, c) => Object.assign(p, { transaction_root: pair(c, Buffer.from('x')).root, steps: pair(c, Buffer.from('x')).steps })), /transaction root other than the certified one/],
    [forged((p, c) => Object.assign(p, { steps: pair(c, Buffer.from('x')).steps })), /its path or leaf does not lead to the certified transaction root/],
    [forged((p) => Object.assign(p, { steps: [{ sibling: '22'.repeat(32), left: true }] })), /its path or leaf does not lead/],
    [forged((p, c) => Object.assign(p, { leaf: sibling(c, Buffer.from(wire.stampArgs(crypto.randomBytes(32), '2'), 'hex')).leaf.toString('hex') })), /its path or leaf does not lead/],
    [forged((p) => Object.assign(p, { leaf: undefined })), /the transaction leaf is not hex/],
    [forged((p) => Object.assign(p, { steps: [{ sibling: '22'.repeat(32), sibling_on_left: true }] })), /does not say which side/],
    [forged(() => []), /no proof was returned/],
  ];
  for (const [override, pattern] of variants) {
    const r = await verifyWith(pinned, receipt, { bytes: record, clients: only(chain, override), trustCustomEndpoints: true }, { helpers: stubHelpers });
    assert.strictEqual(r.status, 'indeterminate', String(pattern));
    assert.strictEqual(qstamp.isProven(r), false);
    assert.match(r.trustDetail, pattern);
  }
  const liar = only(chain, variants[2][0]);
  liar[0].base = 'https://liar.example';
  for (const clients of [liar.concat(only(chain)), only(chain).concat(liar)]) {
    const r = await verifyWith(pinned, receipt, { bytes: record, clients, trustCustomEndpoints: true }, { helpers: stubHelpers });
    assert.strictEqual(r.status, 'valid');
  }
});

test('an included transaction that differs from the receipt refutes it', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('an included but different transaction');
  const receipt = await stamped(chain, record);
  const h = receipt.anchor.height;
  const original = chain.txLeaves.get(h)[0];
  const net = qstamp.NETWORKS.testnet;
  const anchored = qstamp.commitment(Buffer.from(receipt.root, 'hex'), receipt.proof.size, { genesis: net.genesis, contract: net.contract, sender: receipt.anchor.sender, kind: receipt.kind });
  const args = Buffer.from(wire.stampArgs(anchored, receipt.kind), 'hex');
  const cases = [
    [{ from: qcore.core.address(new Uint8Array(32).fill(0x44), 0) }, /it was signed by another account/],
    [{ to: encode('Q', sha3('another contract')) }, /it calls another contract/],
    [{ args: Buffer.from(wire.stampArgs(crypto.randomBytes(32), receipt.kind), 'hex') }, /it does not carry this commitment/],
    [{ kind: 0 }, /it is not a contract call/],
    [{ chainId: chain.numericChainId + 1n }, /it was signed for another chain/],
  ];
  for (const [change, pattern] of cases) {
    const leaf = wrapperBytes(Object.assign({ from: receipt.anchor.sender, to: receipt.contract, args, nonce: 1, chainId: chain.numericChainId }, change));
    chain.txLeaves.get(h)[0] = leaf;
    const forged = JSON.parse(JSON.stringify(receipt));
    forged.anchor.tx = encode('QTX', sha3(leaf));
    chain.txAt.set(forged.anchor.tx, { height: h, index: 0 });
    forged.anchor.block = chain.blocks.get(h).block;
    const r = await verifyWith(pinned, forged, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: stubHelpers });
    assert.strictEqual(r.status, 'invalid', String(pattern));
    assert.match(r.checks.find((c) => c.name === 'finality').detail, pattern);
    assert.match(r.checks.find((c) => c.name === 'finality').detail, /is included under the certified block but/);
  }
  chain.txLeaves.get(h)[0] = original;
  const restored = await verifyWith(pinned, receipt, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(restored.status, 'valid');
});

test('two verified certificates for different blocks at the anchor height refute the anchor in either order', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('an equivocation');
  const receipt = await stamped(chain, record);
  const fork = only(chain, {
    finality: (c, h) => {
      const real = c.finalityAt(Number(h));
      if (Number(h) === 0) return real;
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
  assert.match(r.checks.find((c) => c.name === 'proof').detail, /cannot check finality certificates and transaction inclusion proofs/);
  for (const missing of F.REQUIRED) {
    const partial = Object.assign({}, stubHelpers);
    delete partial[missing];
    const without = await verifyWith(pinned, receipt, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: partial });
    assert.strictEqual(without.status, 'unproven', missing);
    assert.strictEqual(qstamp.isProven(without), false, missing);
  }
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

const OTHER_GENESIS = sha3(Buffer.from('a later genesis that reuses the chain name')).toString('hex');

function genesisNetwork(genesis, roster, extra) {
  return testNetwork({ genesis, finality: Object.assign({ genesis, epochBlocks: 2 ** 40, rosters: { 0: roster || ROSTER } }, extra || {}) });
}

function stampedFor(chain, net, text) {
  const sender = qcore.core.address(SEED, 0);
  const kind = kindValue('document');
  const record = Buffer.from(text);
  const salt = sha3(Buffer.from('salt of ' + text));
  const { root } = tree([leafHash('sha3-256', qstamp.digestBytes(record), salt)]);
  const anchored = commitment(root, 1, { genesis: net.genesis, contract: net.contract, sender, kind });
  const tx = chain.submitCall(sender, net.contract, wire.stampArgs(anchored, kind));
  const at = chain.txs.get(tx);
  const blk = chain.blocks.get(at.height);
  const receipt = {
    format: qstamp.RECEIPT_FORMAT,
    chain: { id: net.chainId, genesis: net.genesis },
    contract: net.contract,
    kind,
    record: { alg: 'sha3-256', digest: qstamp.digestBytes(record).toString('hex'), salt: salt.toString('hex') },
    proof: { index: 0, size: 1, path: [] },
    root: root.toString('hex'),
    anchor: { tx, height: at.height, block: blk.block, time: blk.time, sender },
  };
  return { record, receipt };
}

test('a finality proof served from a chain with another genesis refutes the receipt, even under the same name and validators', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const later = genesisNetwork(OTHER_GENESIS);
  const { record, receipt } = stampedFor(chain, later, 'a stamp made on one genesis for another');
  const r = await verifyWith(later, receipt, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.notStrictEqual(r.status, 'valid');
  assert.strictEqual(qstamp.isProven(r), false);
  const fresh = genesisNetwork(OTHER_GENESIS, ROSTER.map((m) => Object.assign({}, m, { attest_pk: 'dd'.repeat(ML_DSA_65_PK_BYTES) })));
  const control = await verifyWith(fresh, receipt, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.notStrictEqual(control.status, 'valid');
  assert.strictEqual(qstamp.isProven(control), false);
  const honest = await stamped(chain, Buffer.from('a stamp on its own genesis'));
  const relabelled = JSON.parse(JSON.stringify(honest));
  relabelled.chain.genesis = OTHER_GENESIS;
  const moved = await verifyWith(later, relabelled, { bytes: Buffer.from('a stamp on its own genesis'), clients: only(chain), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.notStrictEqual(moved.status, 'valid');
  assert.strictEqual(qstamp.isProven(moved), false);
});

test('a proving endpoint that names no genesis or another chain name never proves a receipt', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a genesis left unsaid');
  const receipt = await stamped(chain, record);
  const silent = only(chain, { nodeInfo: (c) => ({ chain_id: c.chainId, head_height: c.height }) });
  const r = await verifyWith(pinned, receipt, { bytes: record, clients: silent, trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.notStrictEqual(r.status, 'valid');
  assert.strictEqual(qstamp.isProven(r), false);
  const direct = await F.proveAnchor({
    net: pinned, receipt, helpers: stubHelpers, leaf: [], selectors: [wire.STAMPED_SELECTOR], data: '',
    sources: silent.map((c) => ({ client: c, label: c.base })),
  });
  assert.strictEqual(direct.state, 'unavailable');
  assert.match(direct.detail, /did not name the genesis of the chain it serves/);
  const renamed = await F.proveAnchor({
    net: pinned, receipt, helpers: stubHelpers, leaf: [], selectors: [wire.STAMPED_SELECTOR], data: '',
    sources: only(chain).map((c) => ({ client: c, label: c.base, info: { chain_id: 'Q-dev-net-7', genesis_hash: chain.genesis } })),
  });
  assert.strictEqual(renamed.state, 'failed');
});

test('a receipt for a genesis other than the one the rosters are pinned for is refuted before any endpoint is asked', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const receipt = await stamped(chain, Buffer.from('pinned elsewhere'));
  let asked = 0;
  const watcher = only(chain, { finality: (c, h) => { asked += 1; return c.finalityAt(Number(h)); } });
  const sources = watcher.map((c) => ({ client: c, label: c.base }));
  const elsewhere = await F.proveAnchor({ net: genesisNetwork(OTHER_GENESIS), receipt, helpers: stubHelpers, sources });
  assert.strictEqual(elsewhere.state, 'refuted');
  const bare = await F.proveAnchor({ net: { chainId: pinned.chainId, finality: { epochBlocks: 2 ** 40, rosters: { 0: ROSTER } } }, receipt, helpers: stubHelpers, sources });
  assert.strictEqual(bare.state, 'unavailable');
  assert.match(bare.detail, /no genesis is pinned/);
  assert.strictEqual(asked, 0);
  assert.strictEqual(F.pinnedGenesis(pinned), pinned.genesis);
  assert.strictEqual(F.pinnedGenesis(qstamp.NETWORKS.testnet), qstamp.NETWORKS.testnet.finality.genesis);
  assert.strictEqual(qstamp.NETWORKS.testnet.finality.genesis, qstamp.NETWORKS.testnet.genesis);
});

test('a pinned checkpoint ties the proving endpoint to its genesis', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const first = Math.min(...chain.blocks.keys());
  const record = Buffer.from('a checkpointed record');
  const receipt = await stamped(chain, record);
  const hashAt = (h) => sha3(chain.headerAt(h, chain.blocks.get(h).time)).toString('hex');
  const at = (hash) => genesisNetwork(chain.genesis, ROSTER, { checkpoint: { height: first, hash } });
  const good = await verifyWith(at(hashAt(first)), receipt, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(good.status, 'valid');
  assert.strictEqual(qstamp.isProven(good), true);
  const other = sha3(Buffer.from('the checkpoint of another chain')).toString('hex');
  const certifiedElsewhere = await verifyWith(at(other), receipt, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(certifiedElsewhere.status, 'invalid');
  assert.match(certifiedElsewhere.checks.find((c) => c.name === 'finality').detail, /not the pinned checkpoint/);
  const uncertified = only(chain, { finality: (c, h) => (Number(h) === first ? Object.assign(c.finalityAt(first), { certificate: '00' }) : c.finalityAt(Number(h))) });
  const unproven = await verifyWith(at(other), receipt, { bytes: record, clients: uncertified, trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.notStrictEqual(unproven.status, 'valid');
  assert.notStrictEqual(unproven.status, 'invalid');
  assert.ok(unproven.notices.concat(unproven.checks.map((c) => c.detail)).some((n) => /other than the pinned one/.test(n)));
  const missing = only(chain, { finality: (c, h) => (Number(h) === first ? null : c.finalityAt(Number(h))) });
  const absent = await verifyWith(at(hashAt(first)), receipt, { bytes: record, clients: missing, trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.notStrictEqual(absent.status, 'valid');
  assert.strictEqual(qstamp.isProven(absent), false);
});

test('a network refuses a finality pin for another genesis or a malformed checkpoint', () => {
  assert.throws(() => checkNetwork(testNetwork({ finality: { genesis: OTHER_GENESIS, epochBlocks: 2 ** 40, rosters: { 0: ROSTER } } })), /pinned to a genesis other than the genesis of the network/);
  for (const checkpoint of [{ height: -1, hash: '00'.repeat(32) }, { height: 1, hash: 'AA'.repeat(32) }, { height: 1 }, { height: 1.5, hash: '00'.repeat(32) }, []]) {
    assert.throws(() => checkNetwork(genesisNetwork(pinned.genesis, ROSTER, { checkpoint })), /checkpoint gives the height of a certified block/, JSON.stringify(checkpoint));
  }
  assert.doesNotThrow(() => checkNetwork(genesisNetwork(pinned.genesis, ROSTER, { checkpoint: { height: 0, hash: pinned.genesis } })));
  assert.doesNotThrow(() => checkNetwork(testNetwork({ finality: { epochBlocks: 2 ** 40, rosters: { 0: ROSTER } } })));
  assert.throws(() => checkNetwork(testNetwork({ finality: { checkpoint: null, epochBlocks: 2 ** 40, rosters: { 0: ROSTER } } })), /pins validator rosters without a checkpoint/);
  assert.doesNotThrow(() => checkNetwork(testNetwork({ finality: { checkpoint: null, epochBlocks: 2 ** 40, rosters: { 0: [] } } })));
});

test('without a pinned checkpoint the genesis an endpoint names never ties its proof to the pinned genesis', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const later = genesisNetwork(OTHER_GENESIS);
  const { receipt } = stampedFor(chain, later, 'a twin chain that claims the later genesis');
  const claims = only(chain, { nodeInfo: (c) => ({ chain_id: c.chainId, genesis_hash: OTHER_GENESIS, head_height: c.height }) });
  const sources = claims.map((c) => ({ client: c, label: c.base }));
  const unpinned = { chainId: later.chainId, genesis: later.genesis, finality: { genesis: later.genesis, checkpoint: null, epochBlocks: 2 ** 40, rosters: { 0: ROSTER } } };
  const r = await F.proveAnchor({ net: unpinned, receipt, helpers: stubHelpers, sources });
  assert.notStrictEqual(r.state, 'proven');
  const held = await F.proveAnchor({ net: later, receipt, helpers: stubHelpers, sources });
  assert.notStrictEqual(held.state, 'proven');
});

test('no finality request is made while no roster is pinned', async () => {
  const chain = makeChain();
  const record = Buffer.from('no pin yet');
  const receipt = await stamped(chain, record);
  let asked = 0;
  const watcher = only(chain, { finality: () => { asked += 1; return null; } });
  const r = await verifyWith(testNetwork(), receipt, { bytes: record, clients: watcher, trustCustomEndpoints: true }, null);
  assert.strictEqual(r.status, 'unproven');
  assert.strictEqual(asked, 0);
  assert.match(r.checks.find((c) => c.name === 'proof').detail, /no validator roster is pinned/);
});

test('the proof helpers are detected on the client core under their published names', () => {
  const f = () => true;
  const found = F.helpersFrom({ core: { verifyFinality: f, verifyEvent: f, decodeEvent: f, verifyTransaction: f, chainIdFromName: f } });
  assert.ok(F.helpersComplete(found));
  const snake = F.helpersFrom({ verify_finality: f, verify_event: f, decode_event: f, verify_transaction: f, chain_id_from_name: f });
  assert.ok(F.helpersComplete(snake));
  assert.strictEqual(F.helpersComplete(F.helpersFrom({ core: { verifyFinality: f, verifyEvent: f, decodeEvent: f, chainIdFromName: f } })), false);
  const today = F.helpersFrom(qcore);
  assert.ok(F.helpersComplete(today));
  assert.strictEqual(require('@quantovainc/qcore/package.json').version, require('../package.json').dependencies['@quantovainc/qcore']);
  assert.strictEqual(String(qcore.core.chainIdFromName(qstamp.NETWORKS.testnet.chainId)), '5165556344643346461');
  assert.throws(() => qcore.core.chainIdFromName('Q-test-net-1'), /retired/);
  assert.strictEqual(require('@quantovainc/qcore/package.json').version, require('../package.json').dependencies['@quantovainc/qcore']);
  for (const name of ['verifyFinality', 'verifyEvent', 'decodeEvent', 'verifyTransaction', 'chainIdFromName']) assert.strictEqual(typeof qcore.core[name], 'function', name);
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
  assert.strictEqual(quorum.status, 'unproven');
  assert.strictEqual(quorum.trust, 'official-quorum');
  assert.strictEqual(qstamp.isProven(quorum), false);
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

test('a twin chain under the same name and validator keys never proves a receipt, even with a replayed checkpoint and a false genesis claim', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const twin = genesisNetwork(OTHER_GENESIS, ROSTER, { checkpoint: checkpointOf(OTHER_GENESIS) });
  const { record, receipt } = stampedFor(chain, twin, 'a stamp on the twin chain presented for the pinned genesis');
  const liar = only(chain, {
    nodeInfo: (c) => ({ chain_id: c.chainId, genesis_hash: OTHER_GENESIS, head_height: c.height }),
    finality: (c, h) => (Number(h) === 0 ? checkpointReply(c.epoch, c.chainId, OTHER_GENESIS) : c.finalityAt(Number(h))),
  });
  const r = await verifyWith(twin, receipt, { bytes: record, clients: liar, trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.notStrictEqual(r.status, 'valid');
  assert.strictEqual(qstamp.isProven(r), false);
  chain.certify = certificate([1, 2, 3], null, null, OTHER_GENESIS);
  const bound = await verifyWith(twin, receipt, { bytes: record, clients: liar, trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(bound.status, 'valid');
});

test('finality helpers that do not bind certificates to the genesis are never used', async () => {
  const real = F.helpersFrom(qcore);
  assert.strictEqual(F.bindsGenesis(real), true);
  const ignoresGenesis = Object.assign({}, real, { finality: (chainId, genesis, ...rest) => qcore.core.verifyFinality(chainId, CHECK.genesis, ...rest) });
  assert.strictEqual(F.bindsGenesis(ignoresGenesis), false);
  const oldShape = Object.assign({}, real, { finality: (chainId, headerHex, certHex, rosterJson) => qcore.core.verifyFinality(chainId, CHECK.genesis, headerHex, certHex, rosterJson) });
  assert.strictEqual(F.bindsGenesis(oldShape), false);
  assert.strictEqual(F.bindsGenesis({}), false);
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a proof through helpers that ignore the genesis');
  const receipt = await stamped(chain, record);
  const blind = Object.assign({}, stubHelpers, { finality: (chainId, genesis, headerHex, certHex, rosterJson) => (headerHex === CHECK.header ? realFinality(chainId, CHECK.genesis, headerHex, certHex, rosterJson) : stubHelpers.finality(chainId, genesis, headerHex, certHex, rosterJson)) });
  const r = await verifyWith(pinned, receipt, { bytes: record, clients: only(chain), trustCustomEndpoints: true }, { helpers: blind });
  assert.notStrictEqual(r.status, 'valid');
  assert.strictEqual(qstamp.isProven(r), false);
  assert.ok(r.checks.concat(r.notices.map((n) => ({ detail: n }))).some((c) => /do not bind certificates to the genesis/.test(c.detail)));
});

test('substitute proof functions that pass the known certificate but do not bind the genesis on every call are never relied on', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a receipt for substitute proof functions');
  const receipt = await stamped(chain, record);
  const opts = { bytes: record, clients: only(chain), trustCustomEndpoints: true };
  const blindFinality = (chainId, genesis, headerHex, certHex, rosterJson) => stubHelpers.finality(chainId, qstamp.NETWORKS.testnet.genesis, headerHex, certHex, rosterJson);
  const honestForCheck = Object.assign({}, stubHelpers, { finality: throughCheck(blindFinality) });
  const onlyCheck = await verifyWith(pinned, receipt, opts, { helpers: honestForCheck });
  assert.notStrictEqual(onlyCheck.status, 'valid');
  assert.strictEqual(qstamp.isProven(onlyCheck), false);
  let calls = 0;
  const honestAtFirst = Object.assign({}, stubHelpers, { finality: (...args) => (++calls <= 2 ? stubHelpers.finality(...args) : blindFinality(...args)) });
  const firstCalls = await verifyWith(pinned, receipt, opts, { helpers: honestAtFirst });
  assert.strictEqual(qstamp.isProven(firstCalls), false);
  const swapped = Object.assign({}, stubHelpers);
  const pending = verifyWith(pinned, receipt, opts, { helpers: swapped });
  swapped.finality = throughCheck(blindFinality);
  const during = await pending;
  assert.strictEqual(qstamp.isProven(during), false);
  const alwaysIncluded = Object.assign({}, stubHelpers, { event: () => true });
  const broken = only(chain, { eventProof: (c, h, i) => Object.assign(c.eventProofAt(Number(h), Number(i)), { steps: [{ sibling: '22'.repeat(32), left: true }], event_count: 2 }) });
  const lied = await verifyWith(pinned, receipt, { bytes: record, clients: broken, trustCustomEndpoints: true }, { helpers: alwaysIncluded });
  assert.strictEqual(qstamp.isProven(lied), false);
});

function walker(blocks, check) {
  const calls = [];
  const helpers = Object.assign({}, stubHelpers, {
    nextRoster(chainId, genesis, epochBlocks, epoch, rosterJson, headerHex, certHex, nextJson, proofHex) {
      calls.push(Number(epoch));
      if (epochBlocks !== BigInt(blocks) || typeof chainId !== 'bigint' || genesis !== pinned.genesis) throw new Error('the roster proof is bound to another chain');
      if (check && !check(JSON.parse(rosterJson), JSON.parse(nextJson), proofHex)) throw new Error('the roster commitment does not open');
      return epoch + 1n;
    },
  });
  return { helpers, calls };
}

const rosterReply = (members, extra) => (c, e) => Object.assign({ epoch: e, height: e, members, header_bytes: '0a', certificate: '0b', proof: 'cd' }, extra || {});
const said = (r) => r.notices.concat(r.checks.filter((c) => !c.ok).map((c) => c.detail));
const walkNet = (blocks) => testNetwork({ finality: { epochBlocks: blocks, rosters: { 0: ROSTER } } });
const blocksFor = (receipt) => Math.floor(Number(receipt.anchor.height) / 3);
const walking = (chain, blocks, rosterProof) => only(chain, Object.assign({ finality: (c, h) => Object.assign(c.finalityAt(Number(h)), { epoch: Math.floor(Number(h) / blocks) }) }, rosterProof ? { rosterProof } : {}));

test('the roster of a later epoch is walked from the pinned one and every step is checked by the client core', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a stamp after the pinned epoch');
  const receipt = await stamped(chain, record);
  const blocks = blocksFor(receipt);
  const target = Math.floor(Number(receipt.anchor.height) / blocks);
  assert.strictEqual(target, 3);
  const { helpers, calls } = walker(blocks, (current, next, proof) => proof === 'cd' && current.length === 3 && next.length === 3);
  const opts = { bytes: record, clients: walking(chain, blocks, rosterReply(ROSTER)), trustCustomEndpoints: true };
  const r = await verifyWith(walkNet(blocks), receipt, opts, { helpers });
  assert.strictEqual(r.status, 'valid', JSON.stringify(r));
  assert.deepStrictEqual(calls, Array.from({ length: target }, (_, i) => i));
  const again = await verifyWith(walkNet(blocks), receipt, opts, { helpers });
  assert.strictEqual(again.status, 'valid');
  assert.strictEqual(calls.length, target);
});

test('a roster change the client core refuses never proves a receipt and the roster an endpoint names is never trusted on its own', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a stamp under a forged roster change');
  const receipt = await stamped(chain, record);
  const blocks = blocksFor(receipt);
  const forged = [member(7, '100', 'f7')];
  const cases = [
    [rosterReply(ROSTER, { proof: 'ef' }), /could not be proven from the roster of epoch 0 \(the roster commitment does not open\)/],
    [rosterReply(forged), /could not be proven from the roster of epoch 0/],
    [rosterReply(ROSTER, { epoch: 99 }), /the roster proof is for another epoch/],
    [rosterReply(ROSTER, { proof: 'zz' }), /the roster proof carries no proof/],
    [rosterReply(ROSTER, { members: 'all of them' }), /the roster proof lists no members/],
    [() => { throw new Error('the endpoint is unreachable'); }, /could not serve the roster proof of epoch 1/],
  ];
  for (const [rosterProof, pattern] of cases) {
    const { helpers } = walker(blocks, (current, next, proof) => proof === 'cd' && next.length === 3);
    const r = await verifyWith(walkNet(blocks), receipt, { bytes: record, clients: walking(chain, blocks, rosterProof), trustCustomEndpoints: true }, { helpers });
    assert.strictEqual(r.status, 'unproven', String(pattern));
    assert.ok(said(r).some((n) => pattern.test(n)), String(pattern) + ' ' + JSON.stringify(said(r)));
  }
  const silent = walker(blocks, () => true);
  silent.helpers.nextRoster = () => 0n;
  const quiet = await verifyWith(walkNet(blocks), receipt, { bytes: record, clients: walking(chain, blocks, rosterReply(ROSTER)), trustCustomEndpoints: true }, { helpers: silent.helpers });
  assert.strictEqual(quiet.status, 'unproven');
  assert.ok(said(quiet).some((n) => /did not confirm the roster of epoch 1/.test(n)), JSON.stringify(said(quiet)));
});

test('without a roster proof endpoint or the roster helper a later epoch stays unproven', async () => {
  const chain = makeChain();
  chain.certify = certificate([1, 2, 3]);
  const record = Buffer.from('a stamp without roster proofs');
  const receipt = await stamped(chain, record);
  const blocks = blocksFor(receipt);
  const { helpers } = walker(blocks, () => true);
  const noEndpoint = await verifyWith(walkNet(blocks), receipt, { bytes: record, clients: walking(chain, blocks), trustCustomEndpoints: true }, { helpers });
  assert.strictEqual(noEndpoint.status, 'unproven');
  assert.ok(said(noEndpoint).some((n) => /does not serve roster proofs/.test(n)), JSON.stringify(said(noEndpoint)));
  const noHelper = await verifyWith(walkNet(blocks), receipt, { bytes: record, clients: walking(chain, blocks, rosterReply(ROSTER)), trustCustomEndpoints: true }, { helpers: stubHelpers });
  assert.strictEqual(noHelper.status, 'unproven');
  assert.ok(said(noHelper).some((n) => /cannot check a roster change/.test(n)), JSON.stringify(said(noHelper)));
});

test('a roster is used only with a client core that verifies certificates of its key size', () => {
  const helpers = F.helpersFrom(qcore);
  assert.strictEqual(F.bindsGenesis(helpers), true);
  const roster65 = JSON.parse(require('../lib/finality-check.json').roster);
  const roster87 = JSON.parse(require('../lib/finality-check-87.json').roster);
  assert.strictEqual(F.verifiableKeySize(helpers, roster65), true);
  assert.strictEqual(F.verifiableKeySize(helpers, roster87), false);
});
