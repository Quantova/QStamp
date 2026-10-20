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
const dns = require('dns');
const { checkNetwork } = require('../lib/networks');
const { verifyWith } = require('../lib/verify');
const { makeChain, client, gateway, SEED, testNetwork } = require('./chain');

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
    '::ffff:0:a00:5': 'private', '::ffff:0:7f00:1': 'loopback', '::ffff:0:a9fe:a9fe': 'linklocal', '::ffff:0:808:808': 'public',
    '64:ff9b::a00:5': 'private', '64:ff9b::808:808': 'public',
  };
  for (const [ip, cls] of Object.entries(cases)) assert.strictEqual(A.classify(ip), cls, ip);
  assert.strictEqual(A.normaliseIp('::ffff:0:10.0.0.5'), '10.0.0.5');
  const refusal = async (rpc) => (await E.endpointsFor({ rpc, trustCustomEndpoints: true }, net, 'verify')).refused;
  assert.match(await refusal('https://[::ffff:0:a00:5]'), /private network address/);
  assert.match(await refusal('https://[64:ff9b::7f00:1]'), /loopback/);
});

test('the local use NAT64 prefix and Teredo are reserved in every layout that can carry an IPv4 address', async () => {
  const layouts = { 48: [6, 7, 9, 10], 56: [7, 9, 10, 11], 64: [9, 10, 11, 12], 96: [12, 13, 14, 15] };
  const v6 = (bytes) => [0, 2, 4, 6, 8, 10, 12, 14].map((i) => ((bytes[i] << 8) | bytes[i + 1]).toString(16)).join(':');
  for (const [bits, at] of Object.entries(layouts)) {
    for (const v4 of [[10, 0, 0, 1], [127, 0, 0, 1], [169, 254, 169, 254], [192, 168, 1, 1], [8, 8, 8, 8]]) {
      const b = [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      v4.forEach((x, i) => { b[at[i]] = x; });
      assert.strictEqual(A.classify(v6(b)), 'reserved', bits + ' ' + v4.join('.'));
    }
  }
  assert.strictEqual(A.classify('2001:0:4136:e378:8000:63bf:3fff:fdd2'), 'reserved');
  assert.strictEqual(A.classify('2001:db8::1'), 'public');
  const refusal = async (rpc) => (await E.endpointsFor({ rpc, trustCustomEndpoints: true, allowLoopback: true, endpointAllowList: [rpc] }, net, 'verify')).refused;
  for (const ip of ['64:ff9b:1:0:a:0:100:0', '64:ff9b:1::a00:5', '64:ff9b:1::808:808', '2001:0:4136:e378:8000:63bf:3fff:fdd2']) {
    assert.match(await refusal('https://[' + ip + ']'), /always refused/, ip);
  }
  const original = dns.lookup;
  let answer = '64:ff9b:1:0:a:0:100:0';
  try {
    dns.lookup = (host, options, callback) => {
      const cb = typeof options === 'function' ? options : callback;
      cb(null, [{ address: answer, family: 6 }]);
    };
    assert.match(await refusal('https://local64.ops.net'), /always refused/);
    answer = '2606:4700::1111';
    const plan = await E.endpointsFor({ rpc: 'https://rebind.ops.net', trustCustomEndpoints: true, trustSingleEndpoint: true }, net, 'verify');
    assert.strictEqual(plan.refused, null);
    answer = '64:ff9b:1:0:a:0:100:0';
    await assert.rejects(E.readerOf(plan.entries[0]).nodeInfo(), (e) => e.reason === 'address refused');
  } finally {
    dns.lookup = original;
  }
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

const twoOperators = (a, b) => testNetwork({ rpcs: [{ url: a, operator: 'Operator A' }, { url: b, operator: 'Operator B' }] });

test('a network that lists one host under two operators is refused whatever form its address takes', () => {
  const pairs = [
    ['http://127.0.0.1:8645', 'http://[::ffff:127.0.0.1]:8645'],
    ['http://127.0.0.1:8645', 'http://127.0.0.1:8646'],
    ['http://127.0.0.1:8645', 'http://LOCALHOST.:8646'],
    ['http://[::1]:8645', 'http://localhost:8645'],
    ['https://203.0.113.5', 'https://[::ffff:cb00:7105]:8443'],
    ['https://203.0.113.5', 'https://203.0.113.5.nip.io'],
    ['https://rpc.ops.example', 'https://RPC.OPS.EXAMPLE.:443/v2'],
  ];
  for (const [a, b] of pairs) {
    assert.throws(() => checkNetwork(twoOperators(a, b), { allowLoopback: true }), /under two operators/, a + ' ' + b);
  }
  assert.strictEqual(checkNetwork(twoOperators('https://203.0.113.5', 'https://203.0.113.6')).rpcs.length, 2);
  assert.strictEqual(checkNetwork(twoOperators('http://127.0.0.1:8645', 'http://[::1]:8646'), { allowLoopback: true }).rpcs.length, 2);
});

test('one server listed twice under two operators never yields an official quorum', async (t) => {
  const chain = makeChain();
  const gw = await gateway(chain);
  t.after(() => gw.close());
  const digest = qstamp.digestBytes(Buffer.from('one host'));
  const [receipt] = await qstamp.stamp({ seed: SEED, index: 0, records: [{ digest }], clients: [client(chain, 'https://a.example'), client(chain, 'https://b.example')], timeoutMs: 1000 });
  for (const second of ['http://[::ffff:127.0.0.1]:' + gw.port, 'http://localhost:' + gw.port, 'http://127.0.0.1:' + gw.port + '/']) {
    const r = await verifyWith(twoOperators(gw.url, second), receipt, { digest, allowLoopback: true }, null);
    assert.notStrictEqual(r.status, 'valid', second);
    assert.strictEqual(qstamp.isProven(r), false, second);
    assert.notStrictEqual(r.trust, 'official-quorum', second);
  }
});

test('official endpoints are grouped by address and host as well as by operator', async () => {
  const sameOperator = testNetwork({ rpcs: [{ url: 'https://203.0.113.5', operator: 'Operator A' }, { url: 'https://[::ffff:203.0.113.5]:8443', operator: 'Operator A' }] });
  const ids = [];
  for (const e of sameOperator.rpcs) ids.push(await E.identify(E.describe(e.url, sameOperator), false));
  assert.ok(ids.every((e) => e.official));
  assert.strictEqual(E.officialGroups(ids).length, 1);
  const apart = twoOperators('https://203.0.113.5', 'https://198.51.100.7');
  const two = [];
  for (const e of apart.rpcs) two.push(await E.identify(E.describe(e.url, apart), false));
  assert.strictEqual(E.officialGroups(two).length, 2);
  const shared = await E.identify(E.describe('https://203.0.113.5', apart), false);
  const forged = Object.assign({}, two[1], { keys: new Set([...two[1].keys, 'ip:203.0.113.5']) });
  assert.strictEqual(E.officialGroups([shared, forged]).length, 1);
});

test('official host names that resolve to one address under two operators are refused', async (t) => {
  const original = dns.lookup;
  t.after(() => { dns.lookup = original; });
  dns.lookup = (host, options, callback) => {
    const cb = typeof options === 'function' ? options : callback;
    cb(null, [{ address: '::ffff:203.0.113.9', family: 6 }]);
  };
  const named = twoOperators('https://rpc.alpha-ops.net', 'https://node.beta-ops.org');
  const plan = await E.endpointsFor({}, named, 'verify');
  assert.match(plan.refused, /one host listed under two operators/);
});

test('an address claimed by one group of endpoints is refused to another when a connection is opened', async () => {
  const apart = twoOperators('https://203.0.113.5', 'https://198.51.100.7');
  const plan = await E.endpointsFor({}, apart, 'verify');
  assert.strictEqual(plan.refused, null);
  assert.strictEqual(plan.groups.length, 2);
  const [a, b] = plan.entries;
  assert.strictEqual(a.permits('203.0.113.5'), true);
  assert.strictEqual(a.permits('198.51.100.7'), false);
  assert.strictEqual(a.permits('::ffff:198.51.100.7'), false);
  assert.strictEqual(b.permits('198.51.100.7'), true);
  assert.strictEqual(a.permits('192.0.2.44'), true);
  assert.strictEqual(b.permits('[::ffff:c000:22c]'), false);
});

test('chain time floors are keyed on the identity of each endpoint, not on how its url is written', async () => {
  const now = Math.floor(Date.now() / 1000);
  let t = now - 1;
  const clock = (base) => ({
    base,
    nodeInfo: async () => ({ chain_id: net.chainId, genesis_hash: net.genesis, head_height: 50 }),
    block: async (h) => ({ height: h, time: t, block: 'QBK1X' }),
    transaction: async () => null,
  });
  const read = (bases) => qstamp.chainTime({ clients: bases.map(clock), trustCustomEndpoints: true });
  await read(['https://a.floor-one.example', 'https://203.0.113.77']);
  t = now - 25;
  const variants = [
    ['https://a.floor-one.example/', 'https://203.0.113.77'],
    ['https://A.FLOOR-ONE.EXAMPLE.', 'https://203.0.113.77'],
    ['https://a.floor-one.example:443/v1', 'https://[::ffff:203.0.113.77]'],
    ['https://[::ffff:cb00:714d]:443', 'https://a.floor-one.example'],
  ];
  for (const bases of variants) await assert.rejects(read(bases), /earlier than/, bases.join(' '));
  const ids = ['https://Node.Example.:443/x', 'https://node.example'].map((u) => E.floorIdentity(E.describe(u, net)));
  assert.strictEqual(ids[0], ids[1]);
  assert.strictEqual(E.floorIdentity(E.describe('http://[::ffff:127.0.0.1]:8645/', net)), E.floorIdentity(E.describe('http://127.0.0.1:8645', net)));
  assert.notStrictEqual(E.floorIdentity(E.describe('https://node.example:8443', net)), ids[0]);
});

test('the chain time floors of official endpoint sets are never pushed out by other sets', () => {
  const key = net.genesis + '\nofficial floor test';
  E.floorSet(key, 1234, true);
  for (let i = 0; i < E.FLOOR_LIMIT + 50; i += 1) E.floorSet(net.genesis + '\ncustom ' + i, i, false);
  assert.strictEqual(E.floorGet(key, true), 1234);
  assert.strictEqual(E.floorGet(net.genesis + '\ncustom 0', false), undefined);
  assert.ok(E.OFFICIAL_FLOOR_LIMIT > 0 && E.OFFICIAL_FLOOR_LIMIT <= E.FLOOR_LIMIT);
});

test('a name lookup that never answers cannot hold verification past its deadline', async () => {
  const chain = makeChain();
  const [receipt] = await qstamp.stamp({ seed: SEED, index: 0, records: [{ digest: qstamp.digestBytes(Buffer.from('slow name')) }], kind: 'document', clients: [client(chain, 'https://alpha.example'), client(chain, 'https://beta.example')], timeoutMs: 1000 });
  const real = dns.lookup;
  dns.lookup = () => {};
  try {
    const started = Date.now();
    const r = await qstamp.verify(receipt, { bytes: Buffer.from('slow name'), deadlineMs: 400 });
    assert.notStrictEqual(r.status, 'valid');
    assert.ok(Date.now() - started < 1500, 'verification took ' + (Date.now() - started) + ' ms');
  } finally {
    dns.lookup = real;
  }
});
