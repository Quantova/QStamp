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
const { testNetwork, encode, sha3 } = require('./chain');
const V = require('./vectors/finality.json');

const helpers = F.helpersFrom(qcore);
const S = V.scenarios;
const ML_DSA_65_PK_BYTES = 1952;
const ML_DSA_65_SIG_BYTES = 3309;

function pinnedFor(roster) {
  return testNetwork({ finality: { epochBlocks: V.epoch_blocks, rosters: { [V.epoch]: V.rosters[roster] } } });
}

function finalityOf(s, block) {
  return JSON.parse(helpers.finality(BigInt(V.chain.id), block.header_bytes, block.certificate, JSON.stringify(V.rosters[s.roster])));
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
    get_finality: (b) => (b.height === V.height ? {
      height: V.height, epoch: V.epoch, chain_id: V.chain.name, header_bytes: block.header_bytes, header_hash: block.header_hash, certificate: block.certificate,
    } : null),
    get_event_proof: (b) => (b.height === V.height && b.index === block.index ? {
      height: V.height, index: block.index, event_count: block.event_count, event_root: block.event_root, leaf: block.leaf, steps: block.steps,
    } : null),
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

async function check(s, endpoints, extra) {
  const gws = await Promise.all(endpoints.map((over) => serve(s, over)));
  const rpc = gws.map((g, i) => (i % 2 === 0 ? 'http://127.0.0.1:' : 'http://localhost:') + g.port);
  const opts = Object.assign({ bytes: Buffer.from(s.record, 'hex'), rpc, trustCustomEndpoints: true, allowLoopback: true }, extra || {});
  if (rpc.length === 1) opts.trustSingleEndpoint = true;
  try {
    return await verifyWith(pinnedFor(s.roster), s.receipt, opts, null);
  } finally {
    await Promise.all(gws.map((g) => g.close()));
  }
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
  const take = (name, n, signed) => {
    out.push({ name, at, len: n, signed: signed !== false });
    at += n;
  };
  const u64 = () => Number(bytes.readBigUInt64LE(at));
  const blob = (name, signed) => {
    const n = u64();
    take(name + ' length', 8);
    take(name, n, signed);
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
    take(p + 'membership position', 8, false);
    blob(p + 'membership preimage', false);
    const siblings = u64();
    take(p + 'membership path length', 8);
    for (let j = 0; j < siblings; j += 1) blob(p + 'membership sibling ' + j, false);
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
  assert.deepStrictEqual(Object.keys(V.rosters).sort(), ['four', 'three']);
  assert.strictEqual(V.rosters.four.length, 4);
  assert.strictEqual(V.rosters.three.length, 3);
  for (const roster of Object.values(V.rosters)) {
    for (const m of roster) {
      assert.match(m.attest_pk, /^[0-9a-f]+$/);
      assert.strictEqual(m.attest_pk.length, ML_DSA_65_PK_BYTES * 2);
      assert.match(m.stake, /^[1-9][0-9]*$/);
    }
  }
  for (const s of Object.values(S)) {
    assert.strictEqual(s.receipt.anchor.height, V.height);
    assert.strictEqual(s.receipt.anchor.time, V.time);
    assert.strictEqual(s.receipt.anchor.block, encode('QBK', Buffer.from(s.blocks[0].header_hash, 'hex')));
    for (const b of s.blocks) assert.strictEqual(sha3(Buffer.from(b.header_bytes, 'hex')).toString('hex'), b.header_hash);
  }
});

test('the vectors verify directly with the client core helpers', () => {
  const accepted = {
    a_all_sign: ['8000', '8000'],
    b_three_of_four: ['6000', '8000'],
    c_exactly_two_thirds: ['4000', '6000'],
    g_equivocation: ['8000', '8000'],
    h_broken_inclusion: ['8000', '8000'],
    i_other_contract: ['8000', '8000'],
    i_other_selector: ['8000', '8000'],
  };
  const refused = {
    d_below_two_thirds: /less than two thirds of the stake/,
    e_keys_outside_roster: /signature does not verify/,
    e_ids_outside_roster: /validator outside the roster/,
    f_other_chain_id: /signature does not verify/,
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
        assert.strictEqual(String(f.time), String(header.time), name);
      } else {
        assert.throws(() => helpers.finality(BigInt(V.chain.id), b.header_bytes, b.certificate, JSON.stringify(V.rosters[s.roster])), refused[name], name);
      }
      assert.strictEqual(b.event_root, header.eventRoot.toString('hex'), name);
      assert.strictEqual(b.steps.length, F.pathLength(b.event_count, b.index), name);
      assert.strictEqual(helpers.event(b.event_root, b.leaf, JSON.stringify(b.steps)), name !== 'h_broken_inclusion', name);
      const event = JSON.parse(helpers.decode(b.leaf));
      const listed = s.events[b.index];
      assert.deepStrictEqual([event.contract, String(event.selector).toLowerCase(), String(event.data).toLowerCase()], [listed.contract, listed.selector, listed.data], name);
    }
  }
  const other = BigInt(S.f_other_chain_id.sign_chain_id);
  const f = JSON.parse(helpers.finality(other, S.f_other_chain_id.blocks[0].header_bytes, S.f_other_chain_id.blocks[0].certificate, JSON.stringify(V.rosters.four)));
  assert.strictEqual(String(f.signed_stake), '8000');
  assert.strictEqual(helpers.event(S.a_all_sign.blocks[0].event_root, S.a_all_sign.blocks[0].leaf, JSON.stringify(S.a_all_sign.blocks[0].steps.map((st) => Object.assign({}, st, { left: !st.left })))), false);
  assert.strictEqual(JSON.parse(helpers.decode(S.i_other_contract.blocks[0].leaf)).contract === V.chain.contract, false);
  assert.strictEqual(String(JSON.parse(helpers.decode(S.i_other_selector.blocks[0].leaf)).selector).toLowerCase(), wire.COMMITMENT_STAMPED_SELECTOR);
});

test('certificates from all, three of four and exactly two thirds of the stake prove a receipt confirmed by an endpoint', async () => {
  const cases = [
    ['a_all_sign', /8000 of 8000 pinned stake/],
    ['b_three_of_four', /6000 of 8000 pinned stake/],
    ['c_exactly_two_thirds', /4000 of 6000 pinned stake/],
  ];
  for (const [name, pattern] of cases) {
    const r = await check(S[name], [{}, {}]);
    assert.strictEqual(r.status, 'valid', name + ' ' + JSON.stringify(r.notices));
    assert.strictEqual(r.trust, 'finality-proof', name);
    assert.strictEqual(qstamp.isProven(r), true, name);
    assert.strictEqual(r.officialEndpoints, false, name);
    assert.match(r.checks.find((c) => c.name === 'finality').detail, pattern, name);
    assert.ok(r.checks.some((c) => c.ok && /^transaction/.test(c.name)), name);
  }
  const unconfirmed = await check(S.a_all_sign, [{ transaction: () => ({ status: 'unknown' }) }, { transaction: () => ({ status: 'unknown' }) }]);
  assert.strictEqual(unconfirmed.status, 'indeterminate');
  assert.strictEqual(qstamp.isProven(unconfirmed), false);
});

test('certificates below two thirds, from keys or ids outside the roster or for another chain id never prove a receipt', async () => {
  for (const name of ['d_below_two_thirds', 'e_keys_outside_roster', 'e_ids_outside_roster', 'f_other_chain_id']) {
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
  for (const f of cfields) variants.push({ what: 'certificate ' + f.name, certificate: flipped(block.certificate, f.at), signed: f.signed });
  for (let at = 0; at < header.length; at += 1) variants.push({ what: 'header byte ' + at, header: flipped(block.header_bytes, at) });
  const stride = Math.floor(cert.length / 211);
  for (let at = 0; at < cert.length; at += stride) {
    const f = cfields.find((x) => at >= x.at && at < x.at + x.len);
    variants.push({ what: 'certificate byte ' + at + ' in ' + f.name, certificate: flipped(block.certificate, at), signed: f.signed });
  }
  assert.ok(variants.length >= 200 + hfields.length + cfields.length);
  let refusedCount = 0;
  let unsigned = 0;
  for (const v of variants) {
    const headerHex = v.header || block.header_bytes;
    const certHex = v.certificate || block.certificate;
    const mutated = Object.assign({}, block, { header_bytes: headerHex, header_hash: sha3(Buffer.from(headerHex, 'hex')).toString('hex'), certificate: certHex });
    const r = await check(s, [{ block: mutated, shown: block }]);
    let direct = null;
    try {
      direct = finalityOf(s, mutated);
    } catch (e) {
      direct = null;
    }
    if (v.signed === false) {
      unsigned += 1;
      assert.ok(r.status !== 'valid' || (direct && String(direct.hash).toLowerCase() === block.header_hash), v.what);
    } else {
      assert.notStrictEqual(r.status, 'valid', v.what);
      assert.strictEqual(qstamp.isProven(r), false, v.what);
      assert.ok(r.notices.some((n) => /malformed finality proof|finality certificate served by .* does not verify/.test(n)), v.what + ' ' + JSON.stringify(r.notices));
      assert.strictEqual(direct, null, v.what);
      refusedCount += 1;
    }
  }
  assert.ok(refusedCount >= 200, String(refusedCount));
  assert.ok(unsigned > 0);
});
