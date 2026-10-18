// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { core } = require('@quantovainc/qcore');
const qstamp = require('..');
const wire = require('../lib/wire');
const { verifyWith, REVOCATION_TAGS } = require('../lib/verify');
const { makeChain, client, gateway, SEED, testNetwork, encode } = require('./chain');

const net = qstamp.NETWORKS.testnet;

async function stamped(chain, record, extra) {
  const digest = qstamp.digestBytes(record);
  const [receipt] = await qstamp.stamp(Object.assign({
    seed: SEED,
    index: 0,
    records: [{ digest }],
    kind: 'document',
    clients: [client(chain, 'https://alpha.example'), client(chain, 'https://beta.example')],
    timeoutMs: 1000,
  }, extra || {}));
  return receipt;
}

function failing(result) {
  return result.checks.filter((c) => !c.ok);
}

test('a genuine receipt confirmed only by endpoints the caller chose is unproven and never valid', async () => {
  const chain = makeChain();
  const record = Buffer.from('board minutes');
  const receipt = await stamped(chain, record);
  const r = await qstamp.verify(receipt, {
    bytes: record,
    clients: [client(chain, 'https://alpha.example'), client(chain, 'https://beta.example')],
    trustCustomEndpoints: true,
  });
  assert.strictEqual(r.status, 'unproven');
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.proven, false);
  assert.strictEqual(r.trust, 'custom-endpoints');
  assert.strictEqual(qstamp.isProven(r), false);
  assert.strictEqual(r.officialEndpoints, false);
  assert.deepStrictEqual(failing(r).map((c) => [c.name, c.transport]), [['proof', true]]);
});

test('endpoints other than the official ones are not consulted without trustCustomEndpoints', async () => {
  const chain = makeChain();
  const record = Buffer.from('a lease');
  const receipt = await stamped(chain, record);
  let touched = 0;
  const spy = client(chain, 'https://alpha.example', { nodeInfo: (c) => { touched += 1; return { chain_id: c.chainId, genesis_hash: c.genesis, head_height: c.height }; } });
  const r = await qstamp.verify(receipt, { bytes: record, clients: [spy], trustSingleEndpoint: true });
  assert.strictEqual(r.status, 'indeterminate');
  assert.strictEqual(touched, 0);
  assert.match(r.checks.find((c) => c.name === 'endpoints').detail, /trustCustomEndpoints/);
});

test('two host names of one operator count as one operator', async () => {
  const chain = makeChain();
  const record = Buffer.from('an invoice');
  const receipt = await stamped(chain, record);
  const r = await qstamp.verify(receipt, {
    bytes: record,
    clients: [client(chain, 'https://a.ops.example'), client(chain, 'https://b.ops.example')],
    trustCustomEndpoints: true,
  });
  assert.strictEqual(r.status, 'unproven');
  assert.match(r.checks.find((c) => c.name === 'endpoints').detail, /run by 1 operator/);
});

test('a definite negative from one endpoint against a positive from another is indeterminate and names both', async () => {
  const chain = makeChain();
  const record = Buffer.from('a payroll run');
  const receipt = await stamped(chain, record);
  const denies = { transaction: () => ({ status: 'unknown' }), events: () => ({ events: [] }) };
  const denier = client(chain, 'https://denier.example', denies);
  const confirmer = client(chain, 'https://confirmer.example');
  const r = await qstamp.verify(receipt, { bytes: record, clients: [denier, confirmer], trustCustomEndpoints: true });
  assert.strictEqual(r.status, 'indeterminate');
  assert.strictEqual(qstamp.isProven(r), false);
  const agreement = r.checks.find((c) => c.name === 'agreement');
  assert.strictEqual(agreement.ok, false);
  assert.match(agreement.detail, /denier\.example/);
  assert.match(agreement.detail, /confirmer\.example/);
  const both = await qstamp.verify(receipt, { bytes: record, clients: [denier, client(chain, 'https://other.example', denies)], trustCustomEndpoints: true });
  assert.strictEqual(both.status, 'invalid');
});

test('positive endpoints that disagree on the chain data are indeterminate', async () => {
  const chain = makeChain();
  const record = Buffer.from('a shipment');
  const receipt = await stamped(chain, record);
  const odd = client(chain, 'https://odd.example', { transaction: (c, id) => Object.assign({}, c.txs.get(id), { raw: c.txs.get(id).raw + '00' }) });
  const r = await qstamp.verify(receipt, { bytes: record, clients: [client(chain, 'https://even.example'), odd], trustCustomEndpoints: true });
  assert.strictEqual(r.status, 'indeterminate');
  assert.strictEqual(r.checks.find((c) => c.name === 'agreement').ok, false);
});

test('a receipt whose algorithm is not a string is invalid and verify never throws on it', async () => {
  const chain = makeChain();
  const record = Buffer.from('an odd algorithm');
  const receipt = await stamped(chain, record);
  for (const alg of [['sha3-256'], { toString: () => 'sha3-256' }, 1, null]) {
    const bent = JSON.parse(JSON.stringify(receipt));
    bent.record.alg = alg;
    assert.throws(() => qstamp.validateReceipt(JSON.parse(JSON.stringify(bent))), /record\.alg/);
    const r = await qstamp.verify(bent, { bytes: record, clients: [client(chain, 'https://alpha.example')], trustCustomEndpoints: true });
    assert.strictEqual(r.status, 'invalid');
  }
});

test('an endpoint that has not reached the anchor height is not taken as a denial', async () => {
  const chain = makeChain();
  const record = Buffer.from('a filing');
  const receipt = await stamped(chain, record);
  const behind = client(chain, 'https://behind.example', { nodeInfo: (c) => ({ chain_id: c.chainId, genesis_hash: c.genesis, head_height: receipt.anchor.height - 1 }) });
  const r = await qstamp.verify(receipt, { bytes: record, clients: [behind, client(chain, 'https://ahead.example')], trustCustomEndpoints: true });
  assert.strictEqual(r.status, 'unproven');
  assert.ok(r.checks.find((c) => c.name === 'chain @ 1' && !c.ok && c.transport));
});

test('anchors that the history of the chain rules out are invalid before any endpoint is trusted', async () => {
  const chain = makeChain();
  const record = Buffer.from('a contract');
  const receipt = await stamped(chain, record);
  const cases = [
    [{ time: 1577836800 }, /before the genesis/],
    [{ time: Math.floor(Date.now() / 1000) + 3600 }, /in the future/],
    [{ time: net.genesisTime + 60, height: 5000000 }, /higher than the chain can have reached/],
    [{ time: net.genesisTime + 10 * 86400, height: 10 }, /lower than the chain had certainly reached/],
  ];
  for (const [change, pattern] of cases) {
    const forged = JSON.parse(JSON.stringify(receipt));
    Object.assign(forged.anchor, change);
    const r = await qstamp.verify(forged, { bytes: record, clients: [client(chain, 'https://alpha.example')], trustCustomEndpoints: true, trustSingleEndpoint: true });
    assert.strictEqual(r.status, 'invalid', JSON.stringify(change));
    const p = r.checks.find((c) => c.name === 'plausibility');
    assert.strictEqual(p.ok, false);
    assert.match(p.detail, pattern);
  }
});

test('an anchor signed by an account other than the expected issuer is invalid', async () => {
  const chain = makeChain();
  const record = Buffer.from('a certificate');
  const receipt = await stamped(chain, record);
  const other = core.address(new Uint8Array(32).fill(9), 0);
  const opts = { bytes: record, clients: [client(chain, 'https://alpha.example')], trustCustomEndpoints: true };
  const wrong = await qstamp.verify(receipt, Object.assign({ expectedSender: other }, opts));
  assert.strictEqual(wrong.status, 'invalid');
  assert.strictEqual(wrong.checks.find((c) => c.name === 'sender').ok, false);
  const right = await qstamp.verify(receipt, Object.assign({ expectedSender: [other, receipt.anchor.sender] }, opts));
  assert.strictEqual(right.checks.find((c) => c.name === 'sender').ok, true);
  assert.strictEqual(right.status, 'unproven');
});

test('official endpoints run by two different operators that agree make a receipt valid', async (t) => {
  const chain = makeChain();
  const record = Buffer.from('a quarterly report');
  const receipt = await stamped(chain, record);
  const one = await gateway(chain);
  const two = await gateway(chain, { host: '::1' });
  t.after(() => Promise.all([one.close(), two.close()]));
  const official = testNetwork({ rpcs: [{ url: one.url, operator: 'Operator One' }, { url: two.url, operator: 'Operator Two' }] });
  const r = await verifyWith(official, receipt, { bytes: record, allowLoopback: true }, null);
  assert.strictEqual(r.status, 'valid');
  assert.strictEqual(r.trust, 'official-quorum');
  assert.strictEqual(r.officialEndpoints, true);
  assert.strictEqual(qstamp.isProven(r), true);
  assert.deepStrictEqual(r.operators.sort(), ['Operator One', 'Operator Two']);
});

test('official endpoints of a single operator leave the receipt unproven', async (t) => {
  const chain = makeChain();
  const record = Buffer.from('a register entry');
  const receipt = await stamped(chain, record);
  const one = await gateway(chain);
  const two = await gateway(chain);
  t.after(() => Promise.all([one.close(), two.close()]));
  const official = testNetwork({ rpcs: [{ url: one.url, operator: 'Operator One' }, { url: two.url, operator: 'Operator One' }] });
  const r = await verifyWith(official, receipt, { bytes: record, allowLoopback: true }, null);
  assert.strictEqual(r.status, 'unproven');
  assert.strictEqual(r.trust, 'single-endpoint');
  assert.strictEqual(r.officialEndpoints, true);
});

test('officialEndpoints is false as soon as one consulted endpoint is not official', async (t) => {
  const chain = makeChain();
  const record = Buffer.from('a ledger close');
  const receipt = await stamped(chain, record);
  const one = await gateway(chain);
  const two = await gateway(chain, { host: '::1' });
  t.after(() => Promise.all([one.close(), two.close()]));
  const official = testNetwork({ rpcs: [{ url: one.url, operator: 'Operator One' }, { url: two.url, operator: 'Operator Two' }] });
  const mixed = await verifyWith(official, receipt, { bytes: record, clients: [one.url, client(chain, 'https://third.example')], trustCustomEndpoints: true, allowLoopback: true }, null);
  assert.strictEqual(mixed.officialEndpoints, false);
  assert.strictEqual(mixed.status, 'unproven');
  const both = await verifyWith(official, receipt, { bytes: record, rpc: [one.url, two.url], allowLoopback: true }, null);
  assert.strictEqual(both.officialEndpoints, true);
  assert.strictEqual(both.status, 'valid');
});

test('a single official endpoint gives an honest unproven result by default', async (t) => {
  const chain = makeChain();
  const record = Buffer.from('a model card');
  const receipt = await stamped(chain, record);
  const one = await gateway(chain);
  t.after(() => one.close());
  const official = testNetwork({ rpcs: [{ url: one.url, operator: 'Operator One' }] });
  const r = await verifyWith(official, receipt, { bytes: record, allowLoopback: true }, null);
  assert.strictEqual(r.status, 'unproven');
  assert.strictEqual(r.trust, 'single-endpoint');
  assert.strictEqual(r.officialEndpoints, true);
  assert.match(r.trustDetail, /Operator One/);
});

test('remote error text never reaches the result', async (t) => {
  const chain = makeChain();
  const record = Buffer.from('a statement');
  const receipt = await stamped(chain, record);
  const bad = await gateway(chain, { status: 500, reply: { message: 'OPEN THIS LINK http://evil.example/now' } });
  t.after(() => bad.close());
  const official = testNetwork({ rpcs: [{ url: bad.url, operator: 'Operator One' }] });
  const r = await verifyWith(official, receipt, { bytes: record, allowLoopback: true }, null);
  assert.strictEqual(r.status, 'indeterminate');
  const text = JSON.stringify(r);
  assert.ok(!text.includes('OPEN THIS LINK'));
  assert.ok(!text.includes('evil.example'));
  assert.match(r.checks.find((c) => c.name === 'chain').detail, /\(http 500\)/);
});

function customAnchor(chain, contract, record, selector) {
  const sender = core.address(SEED, 0);
  const digest = qstamp.digestBytes(record);
  const prepared = qstamp.prepare([{ digest }]);
  const kind = String(qstamp.KINDS.public_record);
  const anchored = qstamp.commitment(prepared.root, 1, { genesis: chain.genesis, contract, sender, kind });
  chain.customSelector = selector;
  const txId = chain.submitCall(sender, contract, wire.stampArgs(anchored, kind));
  const tx = chain.txs.get(txId);
  const block = chain.blocks.get(tx.height);
  const r = prepared.recs[0];
  return {
    anchored,
    receipt: {
      format: qstamp.RECEIPT_FORMAT,
      chain: { id: chain.chainId, genesis: chain.genesis },
      contract,
      kind,
      record: { alg: r.alg, digest: r.digest.toString('hex'), salt: r.salt.toString('hex') },
      proof: { index: 0, size: 1, path: [] },
      root: prepared.root.toString('hex'),
      anchor: { tx: txId, height: tx.height, block: block.block, time: block.time, sender },
    },
  };
}

test('a commitment withdrawn by the issuer is never valid and the result reports it revoked', async (t) => {
  const chain = makeChain();
  const contract = core.address(new Uint8Array(32).fill(3), 5);
  const record = Buffer.from('a licence');
  const { receipt, anchored } = customAnchor(chain, contract, record, wire.COMMITMENT_STAMPED_SELECTOR);
  const one = await gateway(chain);
  const two = await gateway(chain, { host: '::1' });
  t.after(() => Promise.all([one.close(), two.close()]));
  const official = testNetwork({ rpcs: [{ url: one.url, operator: 'Operator One' }, { url: two.url, operator: 'Operator Two' }] });
  const opts = { bytes: record, contract, trustCustomContract: true, allowLoopback: true };
  const before = await verifyWith(official, receipt, opts, null);
  assert.strictEqual(before.status, 'valid');
  assert.strictEqual(before.revoked, false);
  chain.revoke(contract, REVOCATION_TAGS[wire.COMMITMENT_STAMPED_SELECTOR], anchored.toString('hex'), 7);
  const after = await verifyWith(official, receipt, opts, null);
  assert.strictEqual(after.status, 'invalid');
  assert.deepStrictEqual(after.revoked, { reason: '7' });
  assert.strictEqual(after.checks.find((c) => c.name.startsWith('revocation')).ok, false);
});

test('a stamp recorded with the open event layout, as the council template does, reports withdrawal as not applicable', async (t) => {
  const chain = makeChain();
  const contract = core.address(new Uint8Array(32).fill(4), 2);
  const record = Buffer.from('a permit');
  const { receipt } = customAnchor(chain, contract, record, wire.STAMPED_SELECTOR);
  assert.strictEqual(REVOCATION_TAGS[wire.STAMPED_SELECTOR], undefined);
  let reads = 0;
  const watch = (c, base) => Object.assign(client(c, base), { storageAt: async () => { reads += 1; return { slots: [] }; } });
  const r = await qstamp.verify(receipt, { bytes: record, contract, trustCustomContract: true, clients: [watch(chain, 'https://alpha.example')], trustCustomEndpoints: true });
  assert.strictEqual(r.status, 'unproven');
  assert.strictEqual(r.revoked, null);
  assert.strictEqual(reads, 0);
  assert.match(r.checks.find((c) => c.name === 'revocation').detail, /does not apply/);
  const one = await gateway(chain);
  const two = await gateway(chain, { host: '::1' });
  t.after(() => Promise.all([one.close(), two.close()]));
  const official = testNetwork({ rpcs: [{ url: one.url, operator: 'Operator One' }, { url: two.url, operator: 'Operator Two' }] });
  const quorum = await verifyWith(official, receipt, { bytes: record, contract, trustCustomContract: true, allowLoopback: true }, null);
  assert.strictEqual(quorum.status, 'valid');
  assert.strictEqual(quorum.revoked, null);
});

test('a custom contract receipt cannot be valid when the withdrawal state cannot be read', async () => {
  const chain = makeChain();
  const contract = core.address(new Uint8Array(32).fill(5), 1);
  const record = Buffer.from('a deed');
  const { receipt } = customAnchor(chain, contract, record, wire.COMMITMENT_STAMPED_SELECTOR);
  const r = await qstamp.verify(receipt, { bytes: record, contract, trustCustomContract: true, clients: [client(chain, 'https://alpha.example', { noState: true })], trustCustomEndpoints: true });
  assert.strictEqual(r.status, 'indeterminate');
  assert.ok(r.checks.find((c) => c.name === 'revocation' && c.transport));
});

test('a fabricated anchor never verifies valid through any combination of options', async () => {
  const chain = makeChain();
  const record = Buffer.from('never stamped');
  const sender = core.address(new Uint8Array(32).fill(0x66), 0);
  const digest = qstamp.digestBytes(record);
  const prepared = qstamp.prepare([{ digest }]);
  const kind = '0';
  const anchored = qstamp.commitment(prepared.root, 1, { genesis: net.genesis, contract: net.contract, sender, kind });
  const time = Math.floor(Date.now() / 1000) - 7200;
  const height = Math.floor((time - net.genesisTime) * 4);
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
  const liar = (base, operator) => ({
    base,
    operator,
    nodeInfo: async () => ({ chain_id: net.chainId, genesis_hash: net.genesis, head_height: height + 100 }),
    transaction: async () => ({ status: 'finalised', height, block: receipt.anchor.block, from: sender, to: net.contract, kind: 'call', raw: wire.stampArgs(anchored, kind) }),
    events: async () => ({ events: [{ contract: net.contract, selector: wire.STAMPED_SELECTOR, data: wire.stampedEventData(sender, anchored, kind) }] }),
    block: async () => ({ block: receipt.anchor.block, height, time }),
    storageAt: async () => ({ slots: [] }),
  });
  const sets = [
    [liar('https://one.example')],
    [liar('https://one.example'), liar('https://two.other')],
    [liar(net.rpc, 'Quantova Inc'), liar('https://rpc.second.example', 'Second Operator')],
  ];
  const flags = ['trustSingleEndpoint', 'trustCustomEndpoints', 'trustCustomContract', 'allowLoopback'];
  for (let mask = 0; mask < 1 << flags.length; mask += 1) {
    for (const clients of sets) {
      const o = { bytes: record, clients };
      flags.forEach((f, i) => { if (mask & (1 << i)) o[f] = true; });
      if (o.trustCustomContract) o.contract = net.contract;
      const r = await qstamp.verify(receipt, o);
      assert.notStrictEqual(r.status, 'valid');
      assert.strictEqual(qstamp.isProven(r), false);
    }
  }
});

test('isProven accepts only a valid result reached through a proof or an official quorum', () => {
  assert.strictEqual(qstamp.isProven({ status: 'valid', valid: true, proven: true, trust: 'official-quorum' }), true);
  assert.strictEqual(qstamp.isProven({ status: 'valid', valid: true, proven: true, trust: 'finality-proof' }), true);
  assert.strictEqual(qstamp.isProven({ status: 'valid', valid: true, trust: 'official-quorum' }), false);
  assert.strictEqual(qstamp.isProven({ status: 'unproven', valid: false, proven: false, trust: 'single-endpoint' }), false);
  assert.strictEqual(qstamp.isProven({ status: 'valid', valid: true, proven: true, trust: 'single-endpoint' }), false);
  assert.strictEqual(qstamp.isProven(null), false);
});

function forgedEarlier(receipt, height) {
  return Object.assign({}, receipt, { anchor: Object.assign({}, receipt.anchor, { time: receipt.anchor.time - 5, height }) });
}

test('a receipt claiming an earlier time at a height above the head of every endpoint is invalid, not indeterminate', async (t) => {
  const chain = makeChain();
  const record = Buffer.from('a tender notice');
  const receipt = await stamped(chain, record);
  const forged = forgedEarlier(receipt, chain.height + 50);
  const one = await gateway(chain);
  const two = await gateway(chain, { host: '::1' });
  t.after(() => Promise.all([one.close(), two.close()]));
  const official = testNetwork({ rpcs: [{ url: one.url, operator: 'Operator One' }, { url: two.url, operator: 'Operator Two' }] });
  const r = await verifyWith(official, forged, { bytes: record, allowLoopback: true }, null);
  assert.strictEqual(r.status, 'invalid');
  assert.strictEqual(qstamp.isProven(r), false);
  const denials = r.checks.filter((c) => c.name.startsWith('chain @ '));
  assert.strictEqual(denials.length, 2);
  for (const c of denials) {
    assert.strictEqual(c.ok, false);
    assert.strictEqual(c.transport, false);
    assert.match(c.detail, /later than the anchor time/);
  }
  const custom = await qstamp.verify(forged, { bytes: record, clients: [client(chain, 'https://alpha.example'), client(chain, 'https://beta.example')], trustCustomEndpoints: true });
  assert.strictEqual(custom.status, 'invalid');
  const gap = {
    block: (c, h) => {
      if (Number(h) === c.height) {
        const e = new Error('http 404');
        e.code = 'QSTAMP_TRANSPORT';
        e.reason = 'http 404';
        e.transient = false;
        throw e;
      }
      return Object.assign({}, c.blocks.get(Number(h)));
    },
  };
  const sparse = await qstamp.verify(forged, { bytes: record, clients: [client(chain, 'https://alpha.example', gap), client(chain, 'https://beta.example', gap)], trustCustomEndpoints: true });
  assert.strictEqual(sparse.status, 'invalid');
  const genuine = await verifyWith(official, receipt, { bytes: record, allowLoopback: true }, null);
  assert.strictEqual(genuine.status, 'valid');
});

test('an endpoint that lags behind the anchor and whose head is not later than the anchor time is not taken as a denial', async () => {
  const chain = makeChain();
  const record = Buffer.from('a fresh filing');
  const receipt = await stamped(chain, record);
  const behind = { nodeInfo: (c) => ({ chain_id: c.chainId, genesis_hash: c.genesis, head_height: receipt.anchor.height - 1 }) };
  const lagging = await qstamp.verify(receipt, { bytes: record, clients: [client(chain, 'https://alpha.example', behind), client(chain, 'https://beta.example', behind)], trustCustomEndpoints: true });
  assert.strictEqual(lagging.status, 'indeterminate');
  const lag = lagging.checks.filter((c) => c.name.startsWith('chain @ '));
  assert.strictEqual(lag.length, 2);
  for (const c of lag) {
    assert.strictEqual(c.transport, true);
    assert.match(c.detail, /has not reached the height of the anchor$/);
  }
  const sameSecond = Object.assign({}, behind, {
    block: (c, h) => {
      const b = c.blocks.get(Number(h));
      return b ? Object.assign({}, b, { time: receipt.anchor.time }) : null;
    },
  });
  const tied = await qstamp.verify(receipt, { bytes: record, clients: [client(chain, 'https://alpha.example', sameSecond)], trustCustomEndpoints: true, trustSingleEndpoint: true });
  assert.strictEqual(tied.status, 'indeterminate');
  assert.strictEqual(tied.checks.find((c) => c.name === 'chain').transport, true);
  const silent = Object.assign({}, behind, { block: () => { throw new Error('unavailable'); } });
  const unread = await qstamp.verify(receipt, { bytes: record, clients: [client(chain, 'https://alpha.example', silent)], trustCustomEndpoints: true, trustSingleEndpoint: true });
  assert.strictEqual(unread.status, 'indeterminate');
});

test('a height beyond the block rate of the network is refused before any endpoint is trusted', async () => {
  const chain = makeChain();
  const record = Buffer.from('a contract award');
  const receipt = await stamped(chain, record);
  const t0 = receipt.anchor.time - 5;
  for (const height of [(t0 - net.genesisTime) * 20 + 200, (t0 - net.genesisTime) * 6 + 241, 2 ** 40]) {
    const r = await qstamp.verify(forgedEarlier(receipt, height), { bytes: record, clients: [client(chain, 'https://alpha.example'), client(chain, 'https://beta.example')], trustCustomEndpoints: true });
    assert.strictEqual(r.status, 'invalid', String(height));
    assert.match(r.checks.find((c) => c.name === 'plausibility').detail, /higher than the chain can have reached/);
  }
  assert.ok(net.blocks.maxPerSecond <= 6);
});

test('a network given without bounds for its block heights is refused', async () => {
  const chain = makeChain();
  const record = Buffer.from('a sovereign record');
  const receipt = await stamped(chain, record);
  const base = JSON.parse(JSON.stringify(net));
  for (const drop of ['blocks', 'genesisTime']) {
    const loose = Object.assign({}, base);
    delete loose[drop];
    const r = await verifyWith(loose, receipt, { bytes: record, clients: [client(chain, 'https://alpha.example')], trustCustomEndpoints: true, trustSingleEndpoint: true }, null);
    assert.strictEqual(r.status, 'indeterminate', drop);
    assert.match(r.checks.find((c) => c.name === 'network').detail, /must give/);
  }
  for (const blocks of [{ minPerSecond: 1, maxPerSecond: 0, stallSeconds: 1, slack: 1 }, { minPerSecond: 7, maxPerSecond: 6, stallSeconds: 1, slack: 1 }, { minPerSecond: 1, maxPerSecond: 6, stallSeconds: -1, slack: 1 }, { maxPerSecond: 6 }]) {
    const r = await verifyWith(Object.assign({}, base, { blocks }), receipt, { bytes: record }, null);
    assert.strictEqual(r.status, 'indeterminate', JSON.stringify(blocks));
  }
});
