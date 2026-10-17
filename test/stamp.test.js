// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const qstamp = require('..');
const { makeChain, client, gateway, SEED } = require('./chain');

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
        res.end(JSON.stringify({ chain_id: asked === 1 ? net.chainId : evil, genesis_hash: net.genesis, head_height: 100, fee: { transfer_quon: '10' } }));
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
