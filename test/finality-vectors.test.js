// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const qcore = require('@quantovainc/qcore');
const qstamp = require('..');
const wire = require('../lib/wire');
const F = require('../lib/finality');
const { verifyWith } = require('../lib/verify');
const { decode } = require('../lib/bech32m');
const { testNetwork, encode, sha3, checkpointReply } = require('./chain');
const V = require('./vectors/finality.json');

const helpers = F.helpersFrom(qcore);
const S = V.scenarios;
const ML_DSA_65_PK_BYTES = 1952;
const ML_DSA_65_SIG_BYTES = 3309;

function pinnedFor(roster) {
  return testNetwork({ finality: { epochBlocks: V.epoch_blocks, rosters: { [V.epoch]: roster } } });
}

function finalityOf(s, block) {
  return JSON.parse(helpers.finality(BigInt(V.chain.id), V.chain.genesis, block.header_bytes, block.certificate, JSON.stringify(V.rosters[s.roster])));
}

function serve(s, over) {
  const o = over || {};
  const block = o.block || s.blocks[0];
  let time = V.time;
  try {
    time = F.decodeHeader(Buffer.from(block.header_bytes, 'hex')).time;
  } catch (e) {
    time = V.time;
  }
  const replies = {
    node_info: () => ({ chain_id: V.chain.name, genesis_hash: V.chain.genesis, head_height: V.height + 100 }),
    get_transaction: (b) => (o.transaction ? o.transaction(b) : b.tx_id === s.receipt.anchor.tx ? Object.assign({}, s.transaction) : { status: 'unknown' }),
    get_events: (b) => ({ events: b.height === V.height ? (o.events || s.events).map((e) => Object.assign({}, e)) : [] }),
    get_block: (b) => (b.height === V.height ? { block: encode('QBK', Buffer.from((o.shown || block).header_hash, 'hex')), height: V.height, time: o.shown ? V.time : time } : null),
    get_finality: (b) => (b.height === 0 ? checkpointReply(V.epoch, V.chain.name) : b.height === V.height ? {
      height: V.height, epoch: V.epoch, chain_id: o.finalityChainId === undefined ? V.chain.name : o.finalityChainId, header_bytes: block.header_bytes, header_hash: block.header_hash, certificate: block.certificate,
    } : null),
    get_event_proof: (b) => (b.height === V.height && b.index === block.index ? {
      height: V.height, index: block.index, event_count: block.event_count, event_root: block.event_root, leaf: block.leaf, steps: block.steps,
    } : null),
    get_transaction_proof: (b) => {
      if (o.transactionProof !== undefined) return typeof o.transactionProof === 'function' ? o.transactionProof(b) : o.transactionProof;
      if (o.noTransactionProofs) return null;
      const known = [block.transaction].concat((s.other_transactions || []).map((t) => Object.assign({ transaction_root: block.transaction.transaction_root }, t)));
      const t = known.find((k) => k.tx_id === b.tx_id);
      return t ? { tx_id: t.tx_id, height: V.height, index: t.index, transaction_root: t.transaction_root, leaf: t.leaf, steps: t.steps } : null;
    },
    get_storage_at: () => ({ slots: [] }),
  };
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let body = {};
      try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
      } catch (e) {
        body = {};
      }
      const reply = replies[req.url.replace(/^\/v1\//, '')];
      const value = reply ? reply(body) : null;
      res.writeHead(value ? 200 : 404, { 'content-type': 'application/json' });
      res.end(JSON.stringify(value || { message: 'not found' }));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ port, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

async function check(s, endpoints, extra, roster) {
  const gws = await Promise.all(endpoints.map((over) => serve(s, over)));
  const rpc = gws.map((g, i) => (i % 2 === 0 ? 'http://127.0.0.1:' : 'http://localhost:') + g.port);
  const opts = Object.assign({ bytes: Buffer.from(s.record, 'hex'), rpc, trustCustomEndpoints: true, allowLoopback: true }, extra || {});
  if (rpc.length === 1) opts.trustSingleEndpoint = true;
  try {
    return await verifyWith(pinnedFor(roster || V.rosters[s.roster]), s.receipt, opts, null);
  } finally {
    await Promise.all(gws.map((g) => g.close()));
  }
}

function withTx(s, tx) {
  const receipt = JSON.parse(JSON.stringify(s.receipt));
  receipt.anchor.tx = tx;
  return Object.assign({}, s, { receipt });
}

function proofOf(t, root) {
  return { tx_id: t.tx_id, height: V.height, index: t.index, transaction_root: root || t.transaction_root, leaf: t.leaf, steps: t.steps };
}

function headerFields(bytes) {
  const out = [];
  let at = 0;
  const take = (name, n) => {
    out.push({ name, at, len: n });
    at += n;
  };
  take('height', 8);
  for (const r of ['parent hash', 'q root', 'transaction root', 'event root', 'beacon seed']) take(r, 32);
  const proposer = Number(bytes.readBigUInt64LE(at));
  take('proposer length', 8);
  take('proposer', proposer);
  take('time', 8);
  const extra = Number(bytes.readBigUInt64LE(at));
  take('extra length', 8);
  if (extra) take('extra', extra);
  assert.strictEqual(at, bytes.length);
  return out;
}

function certificateFields(bytes) {
  const out = [];
  let at = 0;
  const take = (name, n, membership) => {
    out.push({ name, at, len: n, membership: membership === true });
    at += n;
  };
  const u64 = () => Number(bytes.readBigUInt64LE(at));
  const blob = (name, membership) => {
    const n = u64();
    take(name + ' length', 8);
    take(name, n, membership);
  };
  const block = (p) => {
    take(p + 'block height', 8);
    take(p + 'block value', 32);
    take(p + 'block parent tag', 1);
    take(p + 'block parent', 32);
    take(p + 'block cost', 8);
  };
  take('envelope height', 8);
  take('envelope slot', 8);
  block('envelope ');
  blob('envelope committee');
  take('stage', 1);
  const count = u64();
  take('attestation count', 8);
  for (let i = 0; i < count; i += 1) {
    const p = 'attestation ' + i + ' ';
    for (const f of ['from', 'height', 'slot', 'view']) take(p + f, 8);
    blob(p + 'committee');
    block(p);
    take(p + 'membership position', 8, true);
    blob(p + 'membership preimage', true);
    const siblings = u64();
    take(p + 'membership path length', 8);
    for (let j = 0; j < siblings; j += 1) blob(p + 'membership sibling ' + j, true);
    blob(p + 'signature');
  }
  take('committee reveal count', 8);
  assert.strictEqual(at, bytes.length);
  return out;
}

function flipped(hex, at) {
  const b = Buffer.from(hex, 'hex');
  b[at] ^= 0x01;
  return b.toString('hex');
}

test('the vectors pin the testnet chain and well formed rosters', () => {
  assert.strictEqual(V.chain.name, qstamp.NETWORKS.testnet.chainId);
  assert.strictEqual(V.chain.genesis, qstamp.NETWORKS.testnet.genesis);
  assert.strictEqual(V.chain.contract, qstamp.NETWORKS.testnet.contract);
  assert.strictEqual(String(helpers.chainId(V.chain.name)), V.chain.id);
  assert.strictEqual(V.epoch, Math.floor(V.height / V.epoch_blocks));
  assert.deepStrictEqual(V.source['Quantova-Chain'], '806cdd956e277cfed818ef30311ecec0b84b003c');
  assert.deepStrictEqual(V.source['QRC-CONSENSUS'], '223e012417d804d2e953445c38c2b87d0bff6b34');
  assert.deepStrictEqual(V.source['Q-Crypto'], '04e5ae26a089df4e4cc8f20f3973b7cbbee594e3');
  assert.deepStrictEqual(Object.keys(V.rosters).sort(), ['four', 'three']);
  assert.strictEqual(V.rosters.four.length, 4);
  assert.strictEqual(V.rosters.three.length, 3);
  for (const roster of Object.values(V.rosters)) {
    for (const m of roster) {
      assert.match(m.attest_pk, /^[0-9a-f]+$/);
      assert.strictEqual(m.attest_pk.length, ML_DSA_65_PK_BYTES * 2);
      assert.match(m.stake, /^[1-9][0-9]*$/);
      assert.match(m.root, /^[0-9a-f]{64}$/);
      assert.match(m.root_slots, /^[1-9][0-9]*$/);
    }
    const served = { epoch: V.epoch, chain_id: V.chain.name, total_stake: String(roster.reduce((sum, m) => sum + BigInt(m.stake), 0n)), members: roster.map((m) => Object.assign({ bond_address: 'Q1' }, m)) };
    assert.deepStrictEqual(F.rosterFromValidatorSet(served, V.epoch, V.chain.name), roster);
    assert.deepStrictEqual(F.parseRoster(roster), roster);
  }
  assert.deepStrictEqual(V.rosters.three, V.rosters.four.slice(0, 3));
  assert.strictEqual(new Set(V.rosters.four.map((m) => m.root)).size, 4);
  for (const s of Object.values(S)) {
    assert.strictEqual(s.receipt.anchor.height, V.height);
    assert.strictEqual(s.receipt.anchor.time, V.time);
    assert.strictEqual(s.receipt.anchor.block, encode('QBK', Buffer.from(s.blocks[0].header_hash, 'hex')));
    for (const b of s.blocks) {
      assert.strictEqual(sha3(Buffer.from(b.header_bytes, 'hex')).toString('hex'), b.header_hash);
      assert.strictEqual(b.transaction.tx_id, s.receipt.anchor.tx);
      assert.strictEqual(b.transaction.transaction_root, F.decodeHeader(Buffer.from(b.header_bytes, 'hex')).transactionRoot.toString('hex'));
      assert.strictEqual(encode('QTX', sha3(Buffer.from(b.transaction.leaf, 'hex'))), b.transaction.tx_id);
    }
  }
  assert.deepStrictEqual(S.a_all_sign.other_transactions.map((t) => t.role), ['neighbour', 'neighbour', 'other target', 'other sender', 'other call', 'neighbour']);
});

test('the vectors verify directly with the client core helpers', () => {
  const accepted = {
    a_all_sign: ['8000', '8000'],
    b_three_of_four: ['6000', '8000'],
    g_equivocation: ['8000', '8000'],
    h_broken_inclusion: ['8000', '8000'],
    i_other_contract: ['8000', '8000'],
    i_other_selector: ['8000', '8000'],
    j_broken_transaction_path: ['8000', '8000'],
  };
  const refused = {
    c_exactly_two_thirds: /two thirds of the stake or less/,
    d_below_two_thirds: /two thirds of the stake or less/,
    e_keys_outside_roster: /signature does not verify/,
    e_ids_outside_roster: /validator outside the roster/,
    f_other_chain_id: /signature does not verify/,
    k_other_genesis: /signature does not verify/,
  };
  assert.deepStrictEqual(Object.keys(accepted).concat(Object.keys(refused)).sort(), Object.keys(S).sort());
  for (const [name, s] of Object.entries(S)) {
    for (const b of s.blocks) {
      const header = F.decodeHeader(Buffer.from(b.header_bytes, 'hex'));
      if (accepted[name]) {
        const f = finalityOf(s, b);
        assert.deepStrictEqual([f.signed_stake, f.total_stake].map(String), accepted[name], name);
        assert.strictEqual(String(f.hash).toLowerCase(), b.header_hash, name);
        assert.strictEqual(String(f.height), String(V.height), name);
        assert.strictEqual(String(f.event_root).toLowerCase(), b.event_root, name);
        assert.strictEqual(String(f.transaction_root).toLowerCase(), b.transaction.transaction_root, name);
        assert.strictEqual(String(f.time), String(header.time), name);
      } else {
        assert.throws(() => helpers.finality(BigInt(V.chain.id), V.chain.genesis, b.header_bytes, b.certificate, JSON.stringify(V.rosters[s.roster])), refused[name], name);
      }
      assert.strictEqual(b.event_root, header.eventRoot.toString('hex'), name);
      assert.strictEqual(b.steps.length, F.pathLength(b.event_count, b.index), name);
      assert.strictEqual(helpers.event(b.event_root, b.leaf, JSON.stringify(b.steps)), name !== 'h_broken_inclusion', name);
      const t = b.transaction;
      assert.strictEqual(helpers.transaction(t.transaction_root, t.tx_id, t.leaf, JSON.stringify(t.steps)), name !== 'j_broken_transaction_path', name);
      const tx = F.decodeTransaction(Buffer.from(t.leaf, 'hex'));
      assert.ok(tx.sender.equals(decode(s.receipt.anchor.sender, 'Q', 32)), name);
      assert.ok(tx.target.equals(decode(V.chain.contract, 'Q', 32)), name);
      assert.strictEqual(tx.args.toString('hex'), s.transaction.raw, name);
      assert.strictEqual(tx.chainId, BigInt(V.chain.id), name);
      assert.strictEqual(tx.kind, 1, name);
      const event = JSON.parse(helpers.decode(b.leaf));
      const listed = s.events[b.index];
      assert.deepStrictEqual([event.contract, String(event.selector).toLowerCase(), String(event.data).toLowerCase()], [listed.contract, listed.selector, listed.data], name);
    }
  }
  const other = BigInt(S.f_other_chain_id.sign_chain_id);
  const f = JSON.parse(helpers.finality(other, V.chain.genesis, S.f_other_chain_id.blocks[0].header_bytes, S.f_other_chain_id.blocks[0].certificate, JSON.stringify(V.rosters.four)));
  assert.strictEqual(String(f.signed_stake), '8000');
  const twin = S.k_other_genesis;
  assert.notStrictEqual(twin.sign_genesis, V.chain.genesis);
  const k = JSON.parse(helpers.finality(BigInt(V.chain.id), twin.sign_genesis, twin.blocks[0].header_bytes, twin.blocks[0].certificate, JSON.stringify(V.rosters.four)));
  assert.strictEqual(String(k.signed_stake), '8000');
  assert.strictEqual(helpers.event(S.a_all_sign.blocks[0].event_root, S.a_all_sign.blocks[0].leaf, JSON.stringify(S.a_all_sign.blocks[0].steps.map((st) => Object.assign({}, st, { left: !st.left })))), false);
  assert.strictEqual(JSON.parse(helpers.decode(S.i_other_contract.blocks[0].leaf)).contract === V.chain.contract, false);
  assert.strictEqual(String(JSON.parse(helpers.decode(S.i_other_selector.blocks[0].leaf)).selector).toLowerCase(), wire.COMMITMENT_STAMPED_SELECTOR);
  const a = S.a_all_sign;
  const root = a.blocks[0].transaction.transaction_root;
  for (const t of a.other_transactions) {
    assert.strictEqual(helpers.transaction(root, t.tx_id, t.leaf, JSON.stringify(t.steps)), true, t.role);
    assert.strictEqual(helpers.transaction(root, a.receipt.anchor.tx, t.leaf, JSON.stringify(t.steps)), false, t.role);
  }
  const elsewhere = a.transaction_elsewhere;
  assert.strictEqual(elsewhere.tx_id, a.receipt.anchor.tx);
  assert.notStrictEqual(elsewhere.transaction_root, root);
  assert.strictEqual(helpers.transaction(elsewhere.transaction_root, elsewhere.tx_id, elsewhere.leaf, JSON.stringify(elsewhere.steps)), true);
  assert.strictEqual(helpers.transaction(root, elsewhere.tx_id, elsewhere.leaf, JSON.stringify(elsewhere.steps)), false);
});

test('certificates from all and three of four of the stake prove a receipt confirmed by an endpoint, exactly two thirds does not', async () => {
  const exact = await check(S.c_exactly_two_thirds, [{}, {}]);
  assert.notStrictEqual(exact.status, 'valid');
  assert.strictEqual(qstamp.isProven(exact), false);
  const cases = [
    ['a_all_sign', /8000 of 8000 pinned stake/],
    ['b_three_of_four', /6000 of 8000 pinned stake/],
  ];
  for (const [name, pattern] of cases) {
    const r = await check(S[name], [{}, {}]);
    assert.strictEqual(r.status, 'valid', name + ' ' + JSON.stringify(r.notices));
    assert.strictEqual(r.trust, 'finality-proof', name);
    assert.strictEqual(qstamp.isProven(r), true, name);
    assert.strictEqual(r.officialEndpoints, false, name);
    assert.match(r.checks.find((c) => c.name === 'finality').detail, pattern, name);
    assert.match(r.checks.find((c) => c.name === 'finality').detail, /the anchoring transaction is included under it/, name);
    assert.ok(r.checks.some((c) => c.ok && /^transaction/.test(c.name)), name);
  }
});

test('a finality proof that names the chain by its numeric id proves a receipt, another numeric id never does', async () => {
  const numeric = String(V.chain.id);
  const r = await check(S.a_all_sign, [{ finalityChainId: numeric }, { finalityChainId: numeric }]);
  assert.strictEqual(r.status, 'valid', JSON.stringify(r.notices));
  assert.strictEqual(r.trust, 'finality-proof');
  for (const other of [String(BigInt(numeric) + 1n), '0' + numeric, numeric + ' ', 'Q-test-net-1']) {
    const x = await check(S.a_all_sign, [{ finalityChainId: other }, { finalityChainId: other }]);
    assert.notStrictEqual(x.status, 'valid', other);
    assert.strictEqual(qstamp.isProven(x), false, other);
  }
});

test('a proven transaction keeps a vector receipt valid when endpoints dispute or cannot confirm it', async () => {
  const s = S.a_all_sign;
  const other = encode('Q', sha3('a different signer'));
  const cases = [
    [{ transaction: () => ({ status: 'unknown' }) }, { transaction: () => ({ status: 'unknown' }) }],
    [{ transaction: () => Object.assign({}, s.transaction, { from: other }) }, { transaction: () => Object.assign({}, s.transaction, { raw: '00' }) }],
    [{ transaction: () => null }, { transaction: () => null }],
    [{ transaction: () => null }],
  ];
  for (const endpoints of cases) {
    const r = await check(s, endpoints);
    assert.strictEqual(r.status, 'valid', JSON.stringify(r.checks));
    assert.strictEqual(r.trust, 'finality-proof');
    assert.strictEqual(qstamp.isProven(r), true);
    assert.ok(r.checks.every((c) => c.ok));
    assert.ok(r.notices.some((n) => /^transaction/.test(n)), JSON.stringify(r.notices));
  }
});

test('a wrong transaction id in a vector receipt is invalid', async () => {
  const s = S.a_all_sign;
  const expected = {
    neighbour: [/it was signed by another account/, /it does not carry this commitment/],
    'other target': [/it calls another contract/],
    'other sender': [/it was signed by another account/],
    'other call': [/it does not carry this commitment/],
  };
  const all = /signed by another account|calls another contract|not a contract call|another chain|does not carry this commitment/g;
  for (const t of s.other_transactions) {
    const r = await check(withTx(s, t.tx_id), [{}, {}]);
    assert.strictEqual(r.status, 'invalid', t.role);
    assert.strictEqual(qstamp.isProven(r), false, t.role);
    const detail = r.checks.find((c) => c.name === 'finality').detail;
    assert.match(detail, /is included under the certified block but/, t.role);
    assert.strictEqual(detail.match(all).length, expected[t.role].length, t.role + ' ' + detail);
    for (const pattern of expected[t.role]) assert.match(detail, pattern, t.role);
  }
  const honest = { transaction: () => ({ status: 'unknown' }) };
  const unknown = await check(withTx(s, encode('QTX', sha3('a transaction that was never sent'))), [honest, honest]);
  assert.strictEqual(unknown.status, 'indeterminate');
  assert.strictEqual(qstamp.isProven(unknown), false);
});

test('a transaction proof for another transaction, a broken path or another root never proves a vector receipt and never refutes it', async () => {
  const s = S.a_all_sign;
  const t = s.blocks[0].transaction;
  const root = t.transaction_root;
  const decoy = s.other_transactions[3];
  const variants = [
    [{ transactionProof: proofOf(decoy, root) }, /the proof is for another transaction/],
    [{ transactionProof: Object.assign(proofOf(decoy, root), { tx_id: t.tx_id }) }, /its path or leaf does not lead to the certified transaction root/],
    [{ transactionProof: Object.assign(proofOf(t), { leaf: decoy.leaf }) }, /its path or leaf does not lead/],
    [{ transactionProof: proofOf(s.transaction_elsewhere) }, /transaction root other than the certified one/],
    [{ transactionProof: proofOf(s.transaction_elsewhere, root) }, /its path or leaf does not lead/],
    [{ transactionProof: Object.assign(proofOf(t), { steps: t.steps.map((st) => Object.assign({}, st, { left: !st.left })) }) }, /its path or leaf does not lead/],
    [{ transactionProof: Object.assign(proofOf(t), { steps: t.steps.slice(1) }) }, /its path or leaf does not lead/],
    [{ transactionProof: Object.assign(proofOf(t), { height: V.height + 1 }) }, /the proof is for another block/],
    [{ transactionProof: Object.assign(proofOf(t), { leaf: flipped(t.leaf, 100) }) }, /its path or leaf does not lead/],
  ];
  for (const [over, pattern] of variants) {
    const r = await check(s, [over, over]);
    assert.strictEqual(r.status, 'indeterminate', String(pattern));
    assert.strictEqual(qstamp.isProven(r), false, String(pattern));
    assert.match(r.trustDetail, pattern);
  }
  const broken = await check(S.j_broken_transaction_path, [{}, {}]);
  assert.strictEqual(broken.status, 'indeterminate');
  assert.strictEqual(qstamp.isProven(broken), false);
  assert.match(broken.trustDetail, /its path or leaf does not lead/);
  for (const order of [[variants[0][0], {}], [{}, variants[0][0]]]) {
    const r = await check(s, order);
    assert.strictEqual(r.status, 'valid');
    assert.strictEqual(qstamp.isProven(r), true);
  }
});

test('a gateway without transaction proofs falls back to endpoints confirming the transaction', async () => {
  const s = S.a_all_sign;
  const older = { noTransactionProofs: true };
  const confirmed = await check(s, [older, older]);
  assert.strictEqual(confirmed.status, 'valid');
  assert.strictEqual(qstamp.isProven(confirmed), true);
  assert.doesNotMatch(confirmed.checks.find((c) => c.name === 'finality').detail, /the anchoring transaction is included/);
  const unknown = Object.assign({ transaction: () => ({ status: 'unknown' }) }, older);
  const unconfirmed = await check(s, [unknown, unknown]);
  assert.strictEqual(unconfirmed.status, 'indeterminate');
  assert.strictEqual(qstamp.isProven(unconfirmed), false);
  assert.match(unconfirmed.trustDetail, /could not serve a transaction inclusion proof \(http 404\)/);
});

test('certificates below two thirds, from keys or ids outside the roster or for another chain id never prove a receipt', async () => {
  for (const name of ['d_below_two_thirds', 'e_keys_outside_roster', 'e_ids_outside_roster', 'f_other_chain_id', 'k_other_genesis']) {
    const r = await check(S[name], [{}, {}]);
    assert.notStrictEqual(r.status, 'valid', name);
    assert.strictEqual(r.status, 'unproven', name);
    assert.strictEqual(qstamp.isProven(r), false, name);
    assert.ok(r.notices.some((n) => /does not verify against the pinned validator roster/.test(n)), name + ' ' + JSON.stringify(r.notices));
  }
});

test('a broken inclusion path or an event from another contract or selector never proves a receipt', async () => {
  const broken = await check(S.h_broken_inclusion, [{}, {}]);
  assert.strictEqual(broken.status, 'unproven');
  assert.ok(broken.notices.some((n) => /is not included under the certified block/.test(n)), JSON.stringify(broken.notices));
  for (const name of ['i_other_contract', 'i_other_selector']) {
    const s = S[name];
    const index = s.blocks[0].index;
    const claimed = s.events.map((e, i) => (i === index ? { contract: V.chain.contract, selector: wire.STAMPED_SELECTOR, data: e.data } : e));
    const truthful = await check(s, [{}, {}]);
    assert.notStrictEqual(truthful.status, 'valid', name);
    assert.strictEqual(qstamp.isProven(truthful), false, name);
    const lying = await check(s, [{ events: claimed }, { events: claimed }]);
    assert.strictEqual(lying.status, 'unproven', name);
    assert.ok(lying.notices.some((n) => /is not the stamp event of this receipt/.test(n)), name + ' ' + JSON.stringify(lying.notices));
  }
});

test('two certified headers at the anchor height are refuted as equivocation in either order', async () => {
  const s = S.g_equivocation;
  assert.strictEqual(s.blocks.length, 2);
  assert.notStrictEqual(s.blocks[0].header_hash, s.blocks[1].header_hash);
  for (const order of [[0, 1], [1, 0]]) {
    const r = await check(s, order.map((i) => ({ block: s.blocks[i] })));
    assert.strictEqual(r.status, 'invalid', JSON.stringify(order));
    assert.strictEqual(qstamp.isProven(r), false);
    assert.match(r.checks.find((c) => c.name === 'finality').detail, /certify 2 different blocks at height 800000, .* so the validators equivocated/);
  }
  const alone = await check(s, [{ block: s.blocks[0] }, { block: s.blocks[0] }]);
  assert.strictEqual(alone.status, 'valid');
});

test('a one byte change in any field of the header or the certificate never proves another block', async () => {
  const s = S.a_all_sign;
  const block = s.blocks[0];
  const header = Buffer.from(block.header_bytes, 'hex');
  const cert = Buffer.from(block.certificate, 'hex');
  const hfields = headerFields(header);
  const cfields = certificateFields(cert);
  assert.strictEqual(cfields.filter((f) => /signature$/.test(f.name)).every((f) => f.len === ML_DSA_65_SIG_BYTES), true);
  const variants = [];
  for (const f of hfields) variants.push({ what: 'header ' + f.name, header: flipped(block.header_bytes, f.at) });
  for (const f of cfields) variants.push({ what: 'certificate ' + f.name, certificate: flipped(block.certificate, f.at), membership: f.membership });
  for (let at = 0; at < header.length; at += 1) variants.push({ what: 'header byte ' + at, header: flipped(block.header_bytes, at) });
  const stride = Math.floor(cert.length / 211);
  for (let at = 0; at < cert.length; at += stride) {
    const f = cfields.find((x) => at >= x.at && at < x.at + x.len);
    variants.push({ what: 'certificate byte ' + at + ' in ' + f.name, certificate: flipped(block.certificate, at), membership: f.membership });
  }
  assert.ok(variants.length >= 200 + hfields.length + cfields.length);
  let refusedCount = 0;
  let membership = 0;
  for (const v of variants) {
    const headerHex = v.header || block.header_bytes;
    const certHex = v.certificate || block.certificate;
    const mutated = Object.assign({}, block, { header_bytes: headerHex, header_hash: sha3(Buffer.from(headerHex, 'hex')).toString('hex'), certificate: certHex });
    const r = await check(s, [{ block: mutated, shown: block }]);
    let direct = null;
    let reason = '';
    try {
      direct = finalityOf(s, mutated);
    } catch (e) {
      direct = null;
      reason = String((e && e.message) || e);
    }
    assert.notStrictEqual(r.status, 'valid', v.what);
    assert.strictEqual(qstamp.isProven(r), false, v.what);
    assert.ok(r.notices.some((n) => /malformed finality proof|finality certificate served by .* does not verify/.test(n)), v.what + ' ' + JSON.stringify(r.notices));
    assert.strictEqual(direct, null, v.what);
    if (v.membership) {
      assert.match(reason, /does not prove its committee membership/, v.what);
      membership += 1;
    }
    refusedCount += 1;
  }
  assert.strictEqual(refusedCount, variants.length);
  assert.ok(refusedCount >= 200 + hfields.length + cfields.length, String(refusedCount));
  assert.ok(membership >= 4 * 8, String(membership));
});

function credentialSpan(fields, i) {
  const p = 'attestation ' + i + ' membership ';
  const parts = fields.filter((f) => f.name.startsWith(p));
  const start = parts[0].at;
  const last = parts[parts.length - 1];
  return [start, last.at + last.len];
}

test('a roster with a wrong root or a certificate with a tampered credential never proves a receipt', async () => {
  const s = S.a_all_sign;
  const block = s.blocks[0];
  const roster = V.rosters.four;
  const at = (i, change) => roster.map((m, k) => (k === i ? Object.assign({}, m, change) : Object.assign({}, m)));
  const rosters = [
    ['a flipped root', at(0, { root: flipped(roster[0].root, 31) })],
    ['the root of another validator', at(1, { root: roster[2].root })],
    ['swapped roots', roster.map((m, k) => Object.assign({}, m, { root: roster[(k + 1) % roster.length].root }))],
    ['a root of another slot count', at(2, { root_slots: String(Number(roster[2].root_slots) * 2) })],
    ['a root of fewer slots', at(3, { root_slots: '1' })],
  ];
  for (const [what, wrong] of rosters) {
    assert.throws(() => helpers.finality(BigInt(V.chain.id), V.chain.genesis, block.header_bytes, block.certificate, JSON.stringify(wrong)), /does not prove its committee membership/, what);
    const r = await check(s, [{}, {}], null, wrong);
    assert.notStrictEqual(r.status, 'valid', what);
    assert.strictEqual(qstamp.isProven(r), false, what);
    assert.ok(r.notices.some((n) => /does not verify against the pinned validator roster/.test(n)), what + ' ' + JSON.stringify(r.notices));
  }
  for (const key of ['root', 'root_slots']) {
    const missing = roster.map((m) => {
      const copy = Object.assign({}, m);
      delete copy[key];
      return copy;
    });
    assert.throws(() => helpers.finality(BigInt(V.chain.id), V.chain.genesis, block.header_bytes, block.certificate, JSON.stringify(missing)), /sortition root|root_slots/, key);
    const r = await check(s, [{}, {}], null, missing);
    assert.strictEqual(r.status, 'indeterminate', key);
    assert.strictEqual(qstamp.isProven(r), false, key);
  }
  const cert = Buffer.from(block.certificate, 'hex');
  const fields = certificateFields(cert);
  const [a0, a1] = [credentialSpan(fields, 0), credentialSpan(fields, 1)];
  assert.strictEqual(a0[1] - a0[0], a1[1] - a1[0]);
  const borrowed = Buffer.from(cert);
  cert.copy(borrowed, a0[0], a1[0], a1[1]);
  const shifted = Buffer.from(cert);
  const position = fields.find((f) => f.name === 'attestation 0 membership position');
  shifted.writeBigUInt64LE(cert.readBigUInt64LE(position.at) + 1n, position.at);
  const preimage = fields.find((f) => f.name === 'attestation 3 membership preimage');
  const sibling = fields.find((f) => f.name === 'attestation 2 membership sibling 0');
  const credentials = [
    ['the credential of another validator', borrowed.toString('hex')],
    ['another slot position', shifted.toString('hex')],
    ['a changed preimage', flipped(block.certificate, preimage.at + preimage.len - 1)],
    ['a changed path', flipped(block.certificate, sibling.at)],
  ];
  for (const [what, certificate] of credentials) {
    const mutated = Object.assign({}, block, { certificate });
    assert.throws(() => finalityOf(s, mutated), /does not prove its committee membership/, what);
    const r = await check(s, [{ block: mutated }, { block: mutated }]);
    assert.notStrictEqual(r.status, 'valid', what);
    assert.strictEqual(qstamp.isProven(r), false, what);
    assert.ok(r.notices.some((n) => /does not verify against the pinned validator roster/.test(n)), what + ' ' + JSON.stringify(r.notices));
  }
  const honest = await check(s, [{}, {}], null, roster);
  assert.strictEqual(honest.status, 'valid');
});
