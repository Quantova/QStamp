// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const { spawnSync } = require('child_process');
const qcore = require('@quantovainc/qcore');
const qstamp = require('..');
const { reader, tlsSettings } = require('../lib/transport');
const { waitFinal, clientWith } = require('../lib/client');
const E = require('../lib/endpoints');
const { makeChain, client, gateway, SEED, testNetwork } = require('./chain');

const net = qstamp.NETWORKS.testnet;
const TX = 'QTX1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function listen(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({
        url: 'http://127.0.0.1:' + server.address().port,
        close: () => new Promise((r) => {
          server.closeAllConnections();
          server.close(r);
        }),
      });
    });
  });
}

function slowloris() {
  return listen((req, res) => {
    req.resume();
    res.writeHead(200, { 'content-type': 'application/json' });
    res.write('{"chain_id":"');
    const t = setInterval(() => res.write('A'), 1000);
    res.on('close', () => clearInterval(t));
  });
}

function pki() {
  const probe = spawnSync('openssl', ['version'], { stdio: 'ignore' });
  if (probe.status !== 0) return null;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qstamp-tls-'));
  const run = (args) => {
    const r = spawnSync('openssl', args, { cwd: dir, stdio: 'ignore' });
    if (r.status !== 0) throw new Error('openssl ' + args[0] + ' failed');
  };
  try {
    fs.writeFileSync(path.join(dir, 'ext.cnf'), 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n');
    fs.writeFileSync(path.join(dir, 'ca.cnf'), '[req]\ndistinguished_name = dn\nx509_extensions = v3_ca\nprompt = no\n[dn]\nCN = qstamp test ca\n[v3_ca]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\nsubjectKeyIdentifier = hash\n');
    run(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'ca.key']);
    run(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'srv.key']);
    run(['req', '-new', '-x509', '-config', 'ca.cnf', '-key', 'ca.key', '-out', 'ca.pem', '-days', '2', '-sha256']);
    run(['req', '-new', '-key', 'srv.key', '-out', 'srv.csr', '-subj', '/CN=127.0.0.1']);
    run(['x509', '-req', '-in', 'srv.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'srv.pem', '-days', '2', '-sha256', '-extfile', 'ext.cnf']);
    return {
      ca: fs.readFileSync(path.join(dir, 'ca.pem')),
      key: fs.readFileSync(path.join(dir, 'srv.key')),
      cert: fs.readFileSync(path.join(dir, 'srv.pem')),
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const loopback = { trustCustomEndpoints: true, allowLoopback: true, trustSingleEndpoint: true };

test('an endpoint that trickles one byte a second is cut off at the deadline', async (t) => {
  const slow = await slowloris();
  t.after(() => slow.close());
  let started = Date.now();
  await assert.rejects(qstamp.chainTime(Object.assign({ rpc: slow.url, deadlineMs: 2000 }, loopback)), (e) => {
    assert.strictEqual(e.code, 'QSTAMP_CHAIN_TIME');
    assert.match(e.message, /deadline passed/);
    return true;
  });
  assert.ok(Date.now() - started < 3000, 'chainTime took ' + (Date.now() - started) + ' ms');

  const chain = makeChain();
  const [receipt] = await qstamp.stamp({ seed: SEED, index: 0, records: [{ digest: Buffer.alloc(32, 9) }], clients: [client(chain, 'https://a.example'), client(chain, 'https://b.example')], timeoutMs: 1000 });
  started = Date.now();
  const r = await qstamp.verify(receipt, Object.assign({ digest: Buffer.alloc(32, 9), rpc: slow.url, deadlineMs: 2000 }, loopback));
  assert.strictEqual(r.status, 'indeterminate');
  assert.ok(Date.now() - started < 3000, 'verify took ' + (Date.now() - started) + ' ms');

  started = Date.now();
  await assert.rejects(qstamp.stamp({ seed: SEED, index: 0, records: [{ digest: Buffer.alloc(32, 8) }], rpc: slow.url, allowLoopback: true, trustSingleEndpoint: true, deadlineMs: 2000 }), /deadline passed/);
  assert.ok(Date.now() - started < 3000, 'stamp took ' + (Date.now() - started) + ' ms');
});

test('an abort signal stops a request at once', async (t) => {
  const slow = await slowloris();
  t.after(() => slow.close());
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 300);
  const started = Date.now();
  await assert.rejects(qstamp.chainTime(Object.assign({ rpc: slow.url, signal: controller.signal }, loopback)), /aborted/);
  assert.ok(Date.now() - started < 1500);
  await assert.rejects(qstamp.chainTime(Object.assign({ rpc: slow.url, signal: controller.signal }, loopback)), /aborted/);
  await assert.rejects(qstamp.chainTime({ signal: {} }), /AbortSignal/);
  await assert.rejects(qstamp.chainTime({ deadlineMs: 5 }), /deadlineMs/);
  for (const bad of [{ deadlineMs: 'soon' }, { deadlineMs: 5 }, { signal: {} }]) {
    const r = await qstamp.verify({}, bad);
    assert.strictEqual(r.status, 'indeterminate');
    assert.strictEqual(r.valid, false);
    assert.strictEqual(qstamp.isProven(r), false);
    assert.match(r.checks[0].detail, /deadlineMs|AbortSignal/);
    assert.deepStrictEqual(Object.keys(r).sort(), ['checks', 'contentChecked', 'endpoints', 'notices', 'officialEndpoints', 'operators', 'proven', 'revoked', 'status', 'trust', 'trustDetail', 'valid']);
  }
  await assert.rejects(qstamp.stamp({ seed: SEED, index: 0, records: [{ digest: Buffer.alloc(32, 5) }], signal: controller.signal, clients: [] }), /aborted/);
});

test('the wait for finality ends at timeoutMs even when the endpoint never answers', async () => {
  const chain = makeChain();
  const hang = { transaction: () => new Promise(() => {}) };
  const started = Date.now();
  await assert.rejects(qstamp.stamp({
    seed: SEED, index: 0, records: [{ digest: Buffer.alloc(32, 7) }], timeoutMs: 1000,
    clients: [client(chain, 'https://a.example', hang), client(chain, 'https://b.example', hang)],
  }), (e) => {
    assert.strictEqual(e.code, 'QSTAMP_PENDING');
    assert.ok(e.pending && e.pending.tx);
    return true;
  });
  assert.ok(Date.now() - started < 2500, 'stamp took ' + (Date.now() - started) + ' ms');
});

test('a constantly rate limited endpoint is polled with backoff and Retry-After is honoured', async (t) => {
  let hits = 0;
  let retryAfter = null;
  const srv = await listen((req, res) => {
    req.resume();
    hits += 1;
    res.writeHead(429, Object.assign({ 'content-type': 'application/json' }, retryAfter ? { 'retry-after': retryAfter } : {}));
    res.end('{}');
  });
  t.after(() => srv.close());
  let started = Date.now();
  assert.strictEqual(await waitFinal(reader(srv.url, () => true), TX, 10000), null);
  assert.ok(hits <= 6, hits + ' requests in ' + (Date.now() - started) + ' ms');
  assert.ok(Date.now() - started <= 10500);
  hits = 0;
  retryAfter = '60';
  started = Date.now();
  assert.strictEqual(await waitFinal(reader(srv.url, () => true), TX, 10000), null);
  assert.strictEqual(hits, 1);
  assert.ok(Date.now() - started < 1000);
});

test('the wait for finality stops on an error that will not pass', async (t) => {
  let hits = 0;
  const srv = await listen((req, res) => {
    req.resume();
    hits += 1;
    res.writeHead(400, { 'content-type': 'application/json' });
    res.end('{}');
  });
  t.after(() => srv.close());
  await assert.rejects(waitFinal(reader(srv.url, () => true), TX, 10000), (e) => e.reason === 'http 400');
  assert.strictEqual(hits, 1);
});

const certs = pki();

test('certificates are checked even with NODE_TLS_REJECT_UNAUTHORIZED set to 0 and a private CA is trusted only when given', { skip: !certs }, async (t) => {
  const chain = makeChain({ time: Math.floor(Date.now() / 1000) - 2 });
  const gw = await gateway(chain, { tls: { key: certs.key, cert: certs.cert } });
  t.after(() => gw.close());
  const before = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  t.after(() => {
    if (before === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = before;
  });
  await assert.rejects(reader(gw.url, () => true).nodeInfo(), (e) => e.reason === 'certificate rejected');
  await assert.rejects(qstamp.chainTime(Object.assign({ rpc: gw.url }, loopback)), /certificate rejected/);
  const trusted = await reader(gw.url, () => true, tlsSettings({ ca: certs.ca })).nodeInfo();
  assert.strictEqual(trusted.chain_id, net.chainId);
  const time = await qstamp.chainTime(Object.assign({ rpc: [{ url: gw.url, ca: certs.ca.toString('utf8') }] }, loopback));
  assert.strictEqual(time.trust, 'custom-endpoints');
  const other = pki();
  await assert.rejects(qstamp.chainTime(Object.assign({ rpc: [{ url: gw.url, ca: other.ca }] }, loopback)), /certificate rejected/);
});

test('per endpoint TLS settings are validated and a private CA never makes an endpoint official', () => {
  assert.throws(() => E.describe({ url: 'https://rpc.example', ca: 5 }, net), /string or a Buffer/);
  assert.throws(() => E.describe({ url: 'https://rpc.example', cert: 'x' }, net), /together/);
  assert.throws(() => E.describe({ url: 'https://rpc.example', cacert: 'x' }, net), /only url, ca, cert and key/);
  assert.throws(() => E.describe({ ca: 'x' }, net), /name its url/);
  assert.strictEqual(E.describe({ url: net.rpc }, net).official, true);
  assert.strictEqual(E.describe({ url: net.rpc, cert: 'c', key: 'k' }, net).official, true);
  const custom = E.describe({ url: net.rpc, ca: 'x' }, net);
  assert.strictEqual(custom.official, false);
  assert.strictEqual(custom.tls.ca, 'x');
});

test('a client core that does not honour the fetch option is refused before any request', async () => {
  let ownRequests = 0;
  class Ignores {
    constructor(base) {
      this.base = base;
    }

    async nodeInfo() {
      ownRequests += 1;
      return { chain_id: 'qstamp-probe' };
    }
  }
  class Refuses {
    constructor(base, options) {
      if (options && options.fetch) throw new Error('unknown option fetch');
      this.base = base;
    }
  }
  class Twice {
    constructor(base, options) {
      this.fetch = options.fetch;
    }

    async nodeInfo() {
      await this.fetch('http://127.0.0.1:0/v1/node_info', { method: 'POST', body: '{}' });
      await this.fetch('http://127.0.0.1:0/v1/node_info', { method: 'POST', body: '{}' });
      return { chain_id: 'qstamp-probe' };
    }
  }
  for (const Stub of [Ignores, Refuses, Twice]) {
    await assert.rejects(clientWith(Stub, 'https://rpc.example', net.chainId, () => true), /does not send its requests through the fetch function/, Stub.name);
  }
  assert.strictEqual(ownRequests, 1);
  const real = await clientWith(qcore.Client, 'https://rpc.example', net.chainId, () => true);
  assert.strictEqual(typeof real.nodeInfo, 'function');
});

test('a client core that would sign under another genesis is never used to stamp', async () => {
  class Loose extends qcore.Client {
    constructor(base, options) {
      const rest = Object.assign({}, options);
      delete rest.genesisHash;
      super(base, rest);
    }
  }
  await assert.rejects(clientWith(Loose, 'https://rpc.example', net.chainId, () => true, null, net.genesis), /does not refuse a gateway that reports another genesis/);
  await assert.rejects(clientWith(qcore.Client, 'https://rpc.example', net.chainId, () => true, null, 'AB'.repeat(32)), /64 lowercase hexadecimal/);
  const held = await clientWith(qcore.Client, 'https://rpc.example', net.chainId, () => true, null, net.genesis);
  assert.strictEqual(typeof held.call, 'function');
});

test('https requests always ask for certificate checks and TLS 1.2 or later', () => {
  const seen = [];
  const original = https.request;
  https.request = (url, options) => {
    seen.push(options);
    throw new Error('stop');
  };
  try {
    reader('https://rpc.example', () => true).nodeInfo().catch(() => {});
  } finally {
    https.request = original;
  }
  assert.strictEqual(seen.length, 1);
  assert.strictEqual(seen[0].rejectUnauthorized, true);
  assert.strictEqual(seen[0].minVersion, 'TLSv1.2');
});

test('a network endpoint may carry its own certificate authority and stays official', { skip: !certs }, async (t) => {
  const chain = makeChain({ time: Math.floor(Date.now() / 1000) - 2 });
  const gw = await gateway(chain, { tls: { key: certs.key, cert: certs.cert } });
  t.after(() => gw.close());
  const pinned = testNetwork({ rpcs: [{ url: gw.url, operator: 'Operator One', ca: certs.ca.toString('utf8') }] });
  const plan = await E.endpointsFor({}, pinned, 'verify');
  assert.strictEqual(plan.refused, null);
  const [entry] = plan.entries;
  assert.strictEqual(entry.official, true);
  assert.strictEqual(entry.operator, 'Operator One');
  assert.strictEqual((await E.readerOf(entry).nodeInfo()).chain_id, net.chainId);
  const bare = testNetwork({ rpcs: [{ url: gw.url, operator: 'Operator One' }] });
  const [plain] = (await E.endpointsFor({}, bare, 'verify')).entries;
  await assert.rejects(E.readerOf(plain).nodeInfo(), (e) => e.reason === 'certificate rejected');
  const other = pki();
  const swapped = E.describe({ url: gw.url, ca: other.ca }, pinned);
  assert.strictEqual(swapped.official, false);
});

test('a deadline is not stretched when the wall clock is set back', async () => {
  const D = require('../lib/deadline');
  const real = Date.now;
  const started = real();
  let calls = 0;
  Date.now = () => {
    calls += 1;
    return calls > 1 ? real() - 3600000 : real();
  };
  try {
    await assert.rejects(D.within(new Promise(() => {}), D.controlOf({ deadlineMs: 300 }, 1000)), (e) => D.isStop(e) || /deadline/i.test(String(e && e.message)));
  } finally {
    Date.now = real;
  }
  assert.ok(real() - started < 2000, String(real() - started));
});
