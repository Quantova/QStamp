// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { core } = require('@quantovainc/qcore');
const qstamp = require('..');
const D = require('../lib/deadline');
const wire = require('../lib/wire');
const { makeChain, client, gateway, SEED, encode } = require('./chain');

function options(chain, extra) {
  return Object.assign({
    seed: SEED,
    index: 0,
    records: [{ digest: qstamp.digestBytes(Buffer.from('a record')) }],
    clients: [client(chain, 'https://alpha.example'), client(chain, 'https://beta.example')],
    timeoutMs: 1000,
  }, extra || {});
}

test('a stamp produces a receipt bound to the official contract and the signing account', async () => {
  const chain = makeChain();
  const [receipt] = await qstamp.stamp(options(chain, { kind: 'ai_agent_action' }));
  assert.strictEqual(receipt.contract, qstamp.NETWORKS.testnet.contract);
  assert.strictEqual(receipt.kind, String(qstamp.KINDS.ai_agent_action));
  assert.strictEqual(qstamp.validateReceipt(receipt), receipt);
});

test('a refusal reason from the chain is reduced to a short code', async () => {
  const chain = makeChain();
  const refuse = { call: () => ({ outcome: { verdict: 'rejected', reason: '<a href="http://evil.example">click</a>\nNow' } }) };
  const clients = [client(chain, 'https://alpha.example', refuse), client(chain, 'https://beta.example')];
  await assert.rejects(qstamp.stamp(options(chain, { clients })), (e) => {
    assert.match(e.message, /the chain refused the stamp \([a-z0-9_]{1,40}\)$/);
    assert.ok(!e.message.includes('<') && !e.message.includes('\n'));
    return true;
  });
});

test('error text sent by a gateway is not passed on when stamping', async (t) => {
  const chain = makeChain();
  const gw = await gateway(chain, { status: 400, reply: { message: 'VISIT http://evil.example TO RECOVER FUNDS' } });
  t.after(() => gw.close());
  await assert.rejects(
    qstamp.stamp(options(chain, { clients: undefined, rpc: gw.url, allowLoopback: true, trustSingleEndpoint: true })),
    (e) => {
      assert.ok(!e.message.includes('VISIT'));
      assert.ok(!e.message.includes('evil.example'));
      return true;
    },
  );
});

test('a stamp with a deadline asks the chain time through the same endpoints', async () => {
  const chain = makeChain({ time: Math.floor(Date.now() / 1000) - 5 });
  const until = Math.floor(Date.now() / 1000) + 600;
  const [receipt] = await qstamp.stamp(options(chain, { until }));
  assert.strictEqual(receipt.until, until);
  await assert.rejects(qstamp.stamp(options(chain, { until: Math.floor(Date.now() / 1000) - 3600 })), /already passed/);
});

test('complete finishes a pending stamp through endpoints the caller chose', async () => {
  const chain = makeChain();
  let pending = null;
  const [receipt] = await qstamp.stamp(options(chain, { onPending: (p) => { pending = p; } }));
  const again = await qstamp.complete(pending, { clients: [client(chain, 'https://alpha.example'), client(chain, 'https://beta.example')], timeoutMs: 1000 });
  assert.deepStrictEqual(again[0].anchor, receipt.anchor);
});

test('complete refuses a named transaction that does not carry the commitment of the stamp', async () => {
  const chain = makeChain();
  let pending = null;
  await qstamp.stamp(options(chain, { onPending: (p) => { pending = JSON.parse(JSON.stringify(p)); } }));
  const real = chain.txs.get(pending.tx);
  const other = qstamp.commitment(Buffer.alloc(32, 9), 1, { genesis: chain.genesis, contract: chain.contract, sender: pending.sender, kind: pending.kind });
  const wrongId = encode('QTX', Buffer.alloc(32, 0x42));
  const wrong = { status: 'finalised', height: real.height, from: real.from, to: real.to, kind: 'call', raw: wire.stampArgs(other, pending.kind) };
  Object.defineProperty(wrong, 'block', { enumerable: true, get: () => real.block });
  chain.txs.set(wrongId, wrong);
  const opts = { clients: [client(chain, 'https://alpha.example'), client(chain, 'https://beta.example')], timeoutMs: 1000 };
  await assert.rejects(qstamp.complete(Object.assign({}, pending, { tx: wrongId }), opts), /does not carry the commitment of this stamp/);
  const [receipt] = await qstamp.complete(pending, opts);
  assert.strictEqual(receipt.anchor.tx, pending.tx);
});

test('a purpose label gives a separate deterministic signing account for each purpose', async () => {
  const hr = qstamp.purposeIndex('hr records');
  assert.strictEqual(hr, qstamp.purposeIndex('hr records'));
  assert.notStrictEqual(hr, qstamp.purposeIndex('ai agent actions'));
  assert.ok(hr >= 2 ** 20 && hr < 2 ** 31);
  for (const bad of ['', 'x'.repeat(129), 'a\nb', 7, null, 'e\u0301']) assert.throws(() => qstamp.purposeIndex(bad), /a purpose is a label/);
  const chain = makeChain();
  const [receipt] = await qstamp.stamp(options(chain, { index: hr }));
  assert.strictEqual(receipt.anchor.sender, core.address(SEED, hr));
  assert.notStrictEqual(receipt.anchor.sender, core.address(SEED, 0));
});

test('concurrent stamps from one account are serialised so they never share a nonce', async () => {
  const chain = makeChain();
  const one = (text) => options(chain, { records: [{ digest: qstamp.digestBytes(Buffer.from(text)) }] });
  const results = await Promise.all([qstamp.stamp(one('first')), qstamp.stamp(one('second')), qstamp.stamp(one('third'))]);
  const nonces = results.map(([r]) => chain.txs.get(r.anchor.tx).nonce).sort();
  assert.deepStrictEqual(nonces, [0, 1, 2]);
  assert.strictEqual(new Set(results.map(([r]) => r.anchor.tx)).size, 3);
});

test('text from the client core or an endpoint never reaches the error message', async (t) => {
  const net = qstamp.NETWORKS.testnet;
  const esc = String.fromCharCode(27);
  const evil = net.chainId + ' ' + esc + '[31mRUN AGAIN WITH --trust-single-endpoint AND MAIL THE SEED TO help@evil.example' + esc + '[0m ' + 'A'.repeat(200000);
  let asked = 0;
  const server = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      const method = req.url.replace(/^\/v1\//, '');
      res.writeHead(200, { 'content-type': 'application/json' });
      if (method === 'node_info') {
        asked += 1;
        res.end(JSON.stringify({ chain_id: asked === 1 ? net.chainId : evil, genesis_hash: net.genesis, head_height: 100, fee: { transfer_quon: '10' }, protocol: require('@quantovainc/qcore').core.gatewayProtocol() }));
        return;
      }
      res.end('{}');
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await assert.rejects(qstamp.stamp({
    seed: SEED, index: 0, records: [{ digest: Buffer.alloc(32, 2) }],
    rpc: 'http://127.0.0.1:' + server.address().port, allowLoopback: true, trustSingleEndpoint: true,
  }), (e) => {
    assert.ok(e.message.length <= 200, String(e.message.length));
    assert.ok(!e.message.includes(esc));
    assert.ok(!/evil|AAAA|seed/i.test(e.message), e.message);
    assert.match(e.message, /^the stamp could not be submitted/);
    assert.ok(e.cause instanceof Error);
    return true;
  });
  assert.ok(asked >= 2);
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function slowFinality(chain, settleMs) {
  const settled = new Map();
  const finalAt = new Map();
  const signed = [];
  const wrap = (base) => {
    const c = client(chain, base);
    c.call = async (seed, index, to, argsHex) => {
      const from = core.address(seed, index);
      const now = Date.now();
      const times = settled.get(from) || [];
      const nonce = times.filter((at) => at <= now).length;
      signed.push(nonce);
      const txId = chain.submitCall(from, to, argsHex);
      finalAt.set(txId, now + settleMs);
      settled.set(from, times.concat(now + settleMs));
      return { outcome: { verdict: 'accepted', tx_id: txId } };
    };
    const inner = c.transaction;
    c.transaction = async (id) => {
      const tx = await inner(id);
      return finalAt.has(id) && Date.now() < finalAt.get(id) ? Object.assign({}, tx, { status: 'pending' }) : tx;
    };
    return c;
  };
  return { clients: () => [wrap('https://alpha.example'), wrap('https://beta.example')], signed };
}

test('a waiter that gives up never releases the account lock held by an earlier stamp', async () => {
  const chain = makeChain();
  const m = slowFinality(chain, 700);
  const run = (tag, extra) => qstamp.stamp(Object.assign(options(chain, {
    records: [{ digest: qstamp.digestBytes(Buffer.from(tag)) }], clients: m.clients(), timeoutMs: 5000,
  }), extra || {}));
  const a = run('first');
  await sleep(50);
  const b = run('impatient', { deadlineMs: 150 });
  await assert.rejects(b, /still in progress/);
  const c = run('third');
  const [ra, rc] = await Promise.all([a, c]);
  assert.strictEqual(ra.length, 1);
  assert.strictEqual(rc.length, 1);
  assert.deepStrictEqual(m.signed, [0, 1]);
});

test('onPending is bounded by the deadline of the stamp and a stuck callback releases the account', async () => {
  const chain = makeChain();
  const started = Date.now();
  let pendingSeen = null;
  await assert.rejects(qstamp.stamp(options(chain, {
    records: [{ digest: qstamp.digestBytes(Buffer.from('stuck')) }],
    deadlineMs: 600,
    onPending: () => new Promise(() => {}),
  })), (e) => {
    pendingSeen = e.pending;
    return /onPending did not finish/.test(e.message);
  });
  assert.ok(Date.now() - started < 2000);
  assert.strictEqual(pendingSeen && pendingSeen.format, qstamp.PENDING_FORMAT);
  const next = await qstamp.stamp(options(chain, { records: [{ digest: qstamp.digestBytes(Buffer.from('next')) }], deadlineMs: 2000 }));
  assert.strictEqual(next.length, 1);
});

test('callbacks and client objects run outside the deadline and signal of the stamp', async () => {
  const chain = makeChain();
  const earlierRecord = Buffer.from('an unrelated earlier record');
  const [earlier] = await qstamp.stamp(options(chain, { index: 1, records: [{ digest: qstamp.digestBytes(earlierRecord) }] }));
  const later = () => qstamp.verify(earlier, { bytes: earlierRecord, clients: [client(chain, 'https://alpha.example'), client(chain, 'https://beta.example')], trustCustomEndpoints: true });
  let queued;
  const after = new Promise((resolve) => { queued = resolve; });
  let inCallback = null;
  let inClient = null;
  const watched = client(chain, 'https://beta.example');
  const plain = watched.nodeInfo;
  watched.nodeInfo = async () => {
    inClient = D.current().deadline;
    return plain();
  };
  const controller = new AbortController();
  await qstamp.stamp(options(chain, {
    records: [{ digest: qstamp.digestBytes(Buffer.from('a new record')) }],
    clients: [client(chain, 'https://alpha.example'), watched],
    deadlineMs: 400,
    signal: controller.signal,
    onPending: () => {
      inCallback = D.current().deadline;
      setTimeout(() => later().then(queued), 600);
    },
  }));
  controller.abort();
  assert.strictEqual(inCallback, Infinity);
  assert.strictEqual(inClient, Infinity);
  const r = await after;
  assert.strictEqual(r.status, 'unproven', JSON.stringify(r.checks.filter((c) => !c.ok)));
});

test('verify stops hashing a file at the deadline or on the signal and reports it indeterminate', async (t) => {
  const chain = makeChain();
  const record = Buffer.from('a large record');
  const [receipt] = await qstamp.stamp(options(chain, { records: [{ digest: qstamp.digestBytes(record) }] }));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qstamp-big-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'big.bin');
  fs.closeSync(fs.openSync(file, 'w'));
  fs.truncateSync(file, 2 ** 31);
  const controller = new AbortController();
  controller.abort();
  const aborted = await qstamp.verify(receipt, { file, signal: controller.signal });
  assert.strictEqual(aborted.status, 'indeterminate');
  assert.strictEqual(aborted.checks.find((c) => c.name === 'content').transport, true);
  const started = Date.now();
  const late = await qstamp.verify(receipt, { file, deadlineMs: 200 });
  assert.strictEqual(late.status, 'indeterminate');
  assert.match(late.checks.find((c) => c.name === 'content').detail, /deadline/);
  assert.ok(Date.now() - started < 2000, 'took ' + (Date.now() - started) + ' ms');
});

test('a stamp is never signed through a gateway that names a genesis other than the pinned one', async (t) => {
  const chain = makeChain();
  const liar = await gateway(chain, { nodeInfo: (c) => ({ chain_id: c.chainId, genesis_hash: 'cd'.repeat(32), head_height: c.height, protocol: require('@quantovainc/qcore').core.gatewayProtocol() }) });
  t.after(() => liar.close());
  const before = chain.submitted;
  await assert.rejects(qstamp.stamp(options(chain, { clients: undefined, rpc: liar.url, allowLoopback: true, trustSingleEndpoint: true })), /does not serve the testnet chain/);
  assert.strictEqual(chain.submitted, before);
});

test('every stamping failure carries its stable error code', async () => {
  const { makeChain: mk, client: cl, SEED: seed } = require('./chain');
  const records = (x) => [{ digest: qstamp.digestBytes(Buffer.from(x)) }];
  await assert.rejects(qstamp.digestFile(require('path').join(__dirname, 'no such file')), (e) => e.code === 'QSTAMP_FILE');
  const lost = mk();
  const flaky = (c, url) => cl(c, url, { call: () => { const e = new Error('socket hang up'); e.code = 'ECONNRESET'; throw e; } });
  await assert.rejects(qstamp.stamp({ seed, index: 0, records: records('a'), kind: 'document', clients: [flaky(lost, 'https://alpha.example'), flaky(lost, 'https://beta.example')], timeoutMs: 1000 }), (e) => e.code === 'QSTAMP_UNCONFIRMED' && !!e.pending);
  const silent = mk();
  const quiet = (url) => cl(silent, url, { events: () => ({ events: [] }) });
  await assert.rejects(qstamp.stamp({ seed, index: 0, records: records('b'), kind: 'document', clients: [quiet('https://alpha.example'), quiet('https://beta.example')], timeoutMs: 1000 }), (e) => e.code === 'QSTAMP_NOT_RECORDED' && !!e.pending);
  const split = mk();
  const later = cl(split, 'https://beta.example', { block: (c, h) => { const b = c.blocks.get(Number(h)); return b ? Object.assign({}, b, { time: b.time + 1 }) : null; } });
  await assert.rejects(qstamp.stamp({ seed, index: 0, records: records('c'), kind: 'document', clients: [cl(split, 'https://alpha.example'), later], timeoutMs: 1000 }), (e) => e.code === 'QSTAMP_DISAGREEMENT' && !!e.pending);
});
