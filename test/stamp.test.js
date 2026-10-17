// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
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
