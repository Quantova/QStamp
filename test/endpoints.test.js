// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const qstamp = require('..');
const A = require('../lib/address');
const E = require('../lib/endpoints');
const { reader } = require('../lib/transport');
const { clientFor } = require('../lib/client');
const { makeChain, client, gateway, SEED } = require('./chain');

const net = qstamp.NETWORKS.testnet;

test('ip addresses written in different forms normalise to one address', () => {
  assert.strictEqual(A.normaliseIp('203.0.113.5'), '203.0.113.5');
  assert.strictEqual(A.normaliseIp('::ffff:203.0.113.5'), '203.0.113.5');
  assert.strictEqual(A.normaliseIp('[::ffff:cb00:7105]'), '203.0.113.5');
  assert.strictEqual(A.normaliseIp('::203.0.113.5'), '203.0.113.5');
  assert.strictEqual(A.normaliseIp('64:ff9b::cb00:7105'), '203.0.113.5');
  assert.strictEqual(A.normaliseIp('2002:cb00:7105::1'), '203.0.113.5');
  assert.strictEqual(A.normaliseIp('2001:DB8::1'), '2001:db8:0:0:0:0:0:1');
  assert.strictEqual(A.hostOf('http://2130706433:80/x'), '127.0.0.1');
  assert.strictEqual(A.hostOf('http://0x7f.1/'), '127.0.0.1');
  assert.strictEqual(A.normaliseIp('256.1.1.1'), null);
  assert.strictEqual(A.normaliseIp('fe80::1%eth0'), null);
});

test('addresses are classified so private, loopback and link local ranges can be refused', () => {
  const cases = {
    '127.0.0.1': 'loopback', '::1': 'loopback', '::ffff:127.0.0.1': 'loopback',
    '10.1.2.3': 'private', '172.16.0.1': 'private', '192.168.1.1': 'private', '100.64.0.1': 'private', 'fd00::1': 'private',
    '169.254.169.254': 'linklocal', 'fe80::1': 'linklocal', '0.0.0.0': 'unspecified', '::': 'unspecified',
    '224.0.0.1': 'multicast', '240.0.0.1': 'reserved', '8.8.8.8': 'public', '2606:4700::1': 'public',
  };
  for (const [ip, cls] of Object.entries(cases)) assert.strictEqual(A.classify(ip), cls, ip);
});

test('translated IPv6 forms are classified by the IPv4 address they carry', async () => {
  const cases = {
    '64:ff9b:1::a00:5': 'private', '64:ff9b:1::7f00:1': 'loopback', '64:ff9b:1::a9fe:a9fe': 'linklocal', '64:ff9b:1::808:808': 'public',
    '::ffff:0:a00:5': 'private', '::ffff:0:7f00:1': 'loopback', '::ffff:0:a9fe:a9fe': 'linklocal', '::ffff:0:808:808': 'public',
    '64:ff9b::a00:5': 'private',
  };
  for (const [ip, cls] of Object.entries(cases)) assert.strictEqual(A.classify(ip), cls, ip);
  assert.strictEqual(A.normaliseIp('64:ff9b:1::a00:5'), '10.0.0.5');
  assert.strictEqual(A.normaliseIp('::ffff:0:10.0.0.5'), '10.0.0.5');
  const refusal = async (rpc) => (await E.endpointsFor({ rpc, trustCustomEndpoints: true }, net, 'verify')).refused;
  assert.match(await refusal('https://[64:ff9b:1::a00:5]'), /private network address/);
  assert.match(await refusal('https://[::ffff:0:a00:5]'), /private network address/);
  assert.match(await refusal('https://[64:ff9b:1::7f00:1]'), /loopback/);
});

test('registrable domains follow multi label public suffixes and wildcard ip services', () => {
  assert.strictEqual(A.registrableDomain('a.rpc.example.com'), 'example.com');
  assert.strictEqual(A.registrableDomain('node.operator.co.uk'), 'operator.co.uk');
  assert.strictEqual(A.registrableDomain('x.y.com.au'), 'y.com.au');
  assert.strictEqual(A.registrableDomain('203.0.113.5.nip.io'), 'nip.io');
  assert.deepStrictEqual(A.embeddedIps('203.0.113.5.nip.io'), ['203.0.113.5']);
  assert.deepStrictEqual(A.embeddedIps('app-203-0-113-5.sslip.io'), ['203.0.113.5']);
  assert.deepStrictEqual(A.embeddedIps('cb007105.nip.io'), ['203.0.113.5']);
  assert.deepStrictEqual(A.embeddedIps('rpc.quantova.org'), []);
});

test('endpoints that share an address, a registrable domain or an operator form one group', async () => {
  const ids = [];
  for (const url of ['https://203.0.113.5', 'https://[::ffff:203.0.113.5]', 'https://203.0.113.5.nip.io', 'https://a.ops.example', 'https://b.ops.example', 'https://other.example']) {
    ids.push(await E.identify(E.describe(url, net), false));
  }
  const groups = E.independentGroups(ids);
  assert.strictEqual(groups.length, 3);
  const named = [
    await E.identify(E.describe({ base: 'https://one.example', operator: 'Acme', transaction() {} }, net), false),
    await E.identify(E.describe({ base: 'https://two.other', operator: 'acme', transaction() {} }, net), false),
  ];
  assert.strictEqual(E.independentGroups(named).length, 1);
});

test('a client object must name its endpoint and is never taken as official', () => {
  assert.throws(() => E.describe({ transaction() {} }, net), /must name the endpoint/);
  assert.throws(() => E.describe({ base: 'ftp://x', transaction() {} }, net), /must name the endpoint/);
  const spoof = E.describe({ base: net.rpc, transaction() {} }, net);
  assert.strictEqual(spoof.official, false);
  const real = E.describe(net.rpc + '/', net);
  assert.strictEqual(real.official, true);
  assert.strictEqual(real.operator, 'Quantova Inc');
  assert.throws(() => E.describe('https://user:pw@rpc.example', net), /without credentials/);
});

test('every built in endpoint names its operator', () => {
  for (const n of Object.values(qstamp.NETWORKS)) {
    assert.ok(Array.isArray(n.rpcs) && n.rpcs.length > 0);
    for (const e of n.rpcs) {
      assert.match(e.url, /^https:\/\//);
      assert.ok(typeof e.operator === 'string' && e.operator.length > 0);
    }
    assert.ok(n.rpcs.some((e) => e.url === n.rpc));
    assert.ok(Object.isFrozen(n.rpcs) && Object.isFrozen(n.rpcs[0]) && Object.isFrozen(n.finality));
  }
});

test('caller supplied endpoints on loopback, private or link local addresses are refused by default', async () => {
  const refused = async (opts) => (await E.endpointsFor(Object.assign({ trustCustomEndpoints: true }, opts), net, 'verify')).refused;
  assert.match(await refused({ rpc: 'http://127.0.0.1:8645' }), /loopback/);
  assert.match(await refused({ rpc: 'http://localhost:8645' }), /loopback/);
  assert.match(await refused({ rpc: 'https://[::1]:8645' }), /loopback/);
  assert.match(await refused({ rpc: 'https://10.0.0.7' }), /private network/);
  assert.match(await refused({ rpc: 'https://[::ffff:192.168.1.1]' }), /private network/);
  assert.match(await refused({ rpc: 'https://169.254.169.254' }), /link/);
  assert.match(await refused({ rpc: 'https://169.254.169.254', allowLoopback: true, endpointAllowList: ['169.254.169.254'] }), /always refused/);
  assert.strictEqual(await refused({ rpc: 'http://127.0.0.1:8645', allowLoopback: true }), null);
  assert.strictEqual(await refused({ rpc: 'https://10.0.0.7', endpointAllowList: ['10.0.0.7'] }), null);
  assert.match(await refused({ rpc: 'https://bad.example', endpointAllowList: ['good.example'] }), /allow list/);
  assert.strictEqual(await refused({ rpc: 'https://good.example/rpc', endpointAllowList: ['https://good.example'] }), null);
});

test('the guarded transport refuses a name that resolves to a loopback address at connect time', async (t) => {
  const chain = makeChain();
  const gw = await gateway(chain);
  t.after(() => gw.close());
  const deny = reader('http://localhost:' + gw.port, () => false);
  await assert.rejects(deny.nodeInfo(), (e) => e.reason === 'address refused');
  const allow = reader('http://localhost:' + gw.port, () => true);
  assert.strictEqual((await allow.nodeInfo()).chain_id, net.chainId);
  await assert.rejects(reader('http://rpc.example', () => true).nodeInfo(), (e) => e.reason === 'plaintext http refused');
});

test('every request of the client core goes through the guarded fetch and asks the address policy each time', async (t) => {
  const chain = makeChain();
  const gw = await gateway(chain);
  t.after(() => gw.close());
  const base = 'http://localhost:' + gw.port;
  const deny = await clientFor(base, net.chainId, () => false);
  for (const ask of [() => deny.nodeInfo(), () => deny.events(chain.height), () => deny.block(chain.height), () => deny.head(), () => deny.transaction(chain.txs.keys().next().value || 'QTX1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')]) {
    await assert.rejects(ask(), (e) => e.reason === 'address refused');
  }
  let open = true;
  let asked = 0;
  const policy = () => {
    asked += 1;
    return open;
  };
  const allow = await clientFor(base, net.chainId, policy);
  assert.strictEqual((await allow.nodeInfo()).chain_id, net.chainId);
  const first = asked;
  assert.ok(first >= 1);
  assert.strictEqual((await allow.block(chain.height)).height, chain.height);
  assert.ok(asked > first);
  open = false;
  await assert.rejects(allow.nodeInfo(), (e) => e.reason === 'address refused');
  await assert.rejects(clientFor('ftp://rpc.example', net.chainId, policy), /http or https/);
  const literal = await clientFor('http://127.0.0.1:' + gw.port, net.chainId, () => false);
  await assert.rejects(literal.nodeInfo(), (e) => e.reason === 'address refused');
  await assert.rejects(reader('http://[::1]:' + gw.port, () => false).nodeInfo(), (e) => e.reason === 'address refused');
});

test('chain time is taken from the latest reading so one endpoint cannot move it back', async () => {
  const now = Math.floor(Date.now() / 1000);
  const clock = (base, t) => ({
    base,
    nodeInfo: async () => ({ chain_id: net.chainId, genesis_hash: net.genesis, head_height: 50 }),
    block: async (h) => ({ height: h, time: t, block: 'QBK1X' }),
    transaction: async () => null,
  });
  await assert.rejects(qstamp.chainTime({ clients: [clock('https://a.example', now), clock('https://b.example', now)] }), /trustCustomEndpoints/);
  const ct = await qstamp.chainTime({ clients: [clock('https://a.example', now - 20), clock('https://b.example', now)], trustCustomEndpoints: true });
  assert.strictEqual(ct.chainMs, now * 1000);
  assert.ok(ct.early >= Math.min(now * 1000, ct.hostMs));
  assert.strictEqual(ct.trust, 'custom-endpoints');
  assert.strictEqual(ct.officialEndpoints, false);
  await assert.rejects(
    qstamp.chainTime({ clients: [clock('https://c.example', now - 60), clock('https://d.example', now)], trustCustomEndpoints: true }),
    /disagree/,
  );
  await assert.rejects(
    qstamp.chainTime({ clients: [clock('https://e.example', now - 60), clock('https://f.example', now - 59)], trustCustomEndpoints: true }),
    /behind the local clock/,
  );
  await assert.rejects(
    qstamp.chainTime({ clients: [clock('https://g.ops.example', now), clock('https://h.ops.example', now)], trustCustomEndpoints: true }),
    /not run independently/,
  );
  assert.strictEqual(E.DEFAULT_SLACK_MS, 30000);
});

test('an endpoint set reporting a future chain time is refused and cannot block other endpoint sets', async () => {
  const now = Math.floor(Date.now() / 1000);
  const clock = (base, t) => ({
    base,
    nodeInfo: async () => ({ chain_id: net.chainId, genesis_hash: net.genesis, head_height: 50 }),
    block: async (h) => ({ height: h, time: t, block: 'QBK1X' }),
    transaction: async () => null,
  });
  await assert.rejects(
    qstamp.chainTime({ clients: [clock('https://ahead-a.example', now + 86400), clock('https://ahead-b.example', now + 86400)], trustCustomEndpoints: true }),
    /ahead of the local clock/,
  );
  await qstamp.chainTime({ clients: [clock('https://edge-a.example', now + 25), clock('https://edge-b.example', now + 25)], trustCustomEndpoints: true });
  const other = await qstamp.chainTime({ clients: [clock('https://calm-a.example', now - 5), clock('https://calm-b.example', now - 5)], trustCustomEndpoints: true });
  assert.strictEqual(other.chainMs, (now - 5) * 1000);
});

test('the chain time floors are kept for at most 1024 endpoint sets', async () => {
  const now = Math.floor(Date.now() / 1000);
  const clock = (base) => ({
    base,
    nodeInfo: async () => ({ chain_id: net.chainId, genesis_hash: net.genesis, head_height: 50 }),
    block: async (h) => ({ height: h, time: now - 1, block: 'QBK1X' }),
    transaction: async () => null,
  });
  for (let i = 0; i < E.FLOOR_LIMIT + 100; i += 1) {
    await qstamp.chainTime({ clients: [clock('https://lru-' + i + '-a.example'), clock('https://lru-' + i + '-b.example')], trustCustomEndpoints: true });
  }
  assert.strictEqual(E.FLOOR_LIMIT, 1024);
  assert.strictEqual(E.floorSize(), 1024);
});

test('a stamp with a deadline read through chosen endpoints cannot move the chain time floor of other endpoints', async () => {
  const now = Math.floor(Date.now() / 1000);
  const clock = (base, t) => ({
    base,
    nodeInfo: async () => ({ chain_id: net.chainId, genesis_hash: net.genesis, head_height: 50 }),
    block: async (h) => ({ height: h, time: t, block: 'QBK1X' }),
    transaction: async () => null,
  });
  const victim = () => ({ clients: [clock('https://victim-a.example', now - 5), clock('https://victim-b.example', now - 5)], trustCustomEndpoints: true });
  assert.strictEqual((await qstamp.chainTime(victim())).chainMs, (now - 5) * 1000);
  const ahead = makeChain({ time: now + 25 });
  const [receipt] = await qstamp.stamp({
    seed: SEED,
    index: 0,
    until: now + 600,
    records: [{ digest: qstamp.digestBytes(Buffer.from('a stamp read ahead')) }],
    clients: [client(ahead, 'https://ahead-a.example'), client(ahead, 'https://ahead-b.example')],
    timeoutMs: 1000,
  });
  assert.strictEqual(receipt.until, now + 600);
  assert.strictEqual((await qstamp.chainTime(victim())).chainMs, (now - 5) * 1000);
});

test('stamping keeps working through endpoints the caller chose, subject to the address policy', async () => {
  const chain = makeChain();
  const receipts = await qstamp.stamp({
    seed: new Uint8Array(32).fill(7),
    index: 0,
    records: [{ digest: qstamp.digestBytes(Buffer.from('x')) }],
    clients: [client(chain, 'https://alpha.example'), client(chain, 'https://beta.example')],
    timeoutMs: 1000,
  });
  assert.strictEqual(receipts.length, 1);
  await assert.rejects(qstamp.stamp({
    seed: new Uint8Array(32).fill(7),
    index: 0,
    records: [{ digest: qstamp.digestBytes(Buffer.from('y')) }],
    clients: [client(chain, 'https://a.same.example'), client(chain, 'https://b.same.example')],
    timeoutMs: 1000,
  }), /not run independently/);
  await assert.rejects(qstamp.stamp({
    seed: new Uint8Array(32).fill(7),
    index: 0,
    records: [{ digest: qstamp.digestBytes(Buffer.from('z')) }],
    rpc: 'http://127.0.0.1:9',
    trustSingleEndpoint: true,
  }), /loopback/);
});
