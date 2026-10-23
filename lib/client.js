// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const crypto = require('crypto');
const { Client, core } = require('@quantovainc/qcore');
const { guardedFetch, errorCode, isTransientCode } = require('./transport');
const D = require('./deadline');

const TRANSIENT = /non JSON|fetch failed|timed out|timeout|ECONNRESET|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN|ENOTFOUND|socket|network|status (429|5[0-9][0-9])/i;
const FIRST_DELAY_MS = 400;
const READ_DELAY_CAP_MS = 4000;
const WAIT_DELAY_CAP_MS = 8000;
const RETRY_AFTER_CAP_MS = 30000;

const PROBE_BASE = 'http://127.0.0.1:0';
const PROTOCOL = typeof core.gatewayProtocol === 'function' ? core.gatewayProtocol() : undefined;
const PROBE_REPLY = JSON.stringify({ chain_id: 'qstamp-probe', genesis_hash: '00', head_height: 0, protocol: PROTOCOL });
const PROBE_MS = 2000;
const honoured = new WeakMap();
const bound = new WeakMap();
const PROBE_GENESIS = 'ab'.repeat(32);
const PROBE_OTHER = 'cd'.repeat(32);

function honoursFetch(ClientClass) {
  if (honoured.has(ClientClass)) return honoured.get(ClientClass);
  const verdict = (async () => {
    let seen = 0;
    const probe = async (url) => {
      seen += 1;
      if (url !== PROBE_BASE + '/v1/node_info') throw new Error('unexpected probe request');
      return new Response(PROBE_REPLY, { status: 200, headers: { 'content-type': 'application/json' } });
    };
    try {
      const client = new ClientClass(PROBE_BASE, { fetch: probe });
      const info = await D.within(client.nodeInfo(), { deadline: D.now() + PROBE_MS, signal: undefined });
      return seen === 1 && !!info && info.chain_id === 'qstamp-probe';
    } catch (e) {
      return false;
    }
  })();
  honoured.set(ClientClass, verdict);
  return verdict;
}

function holdsGenesis(ClientClass) {
  if (bound.has(ClientClass)) return bound.get(ClientClass);
  const verdict = (async () => {
    const asked = [];
    const reply = (body) => new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
    const probe = async (url) => {
      const method = String(url).slice((PROBE_BASE + '/v1/').length);
      asked.push(method);
      if (method === 'node_info') return reply(JSON.stringify({ chain_id: 'qstamp-probe', genesis_hash: PROBE_OTHER, head_height: 100, fee: { transfer_quon: '1000' }, protocol: PROTOCOL }));
      if (method === 'get_account') return reply('{"nonce":0,"balance":"0"}');
      return reply('{"verdict":"accepted","tx_id":"probe"}');
    };
    try {
      const client = new ClientClass(PROBE_BASE, { fetch: probe, expectedChainId: 'qstamp-probe', genesisHash: PROBE_GENESIS });
      const seed = new Uint8Array(32).fill(1);
      const to = core.address(new Uint8Array(32).fill(2), 0);
      const refused = await D.within(Promise.resolve().then(() => client.call(seed, 0, to, '00', 1000, '1000000000')), { deadline: D.now() + PROBE_MS, signal: undefined }).then(() => false, (e) => /reports a genesis hash other than/i.test(String(e && e.message)));
      return refused && !asked.includes('submit_transaction');
    } catch (e) {
      return false;
    }
  })();
  bound.set(ClientClass, verdict);
  return verdict;
}

async function clientWith(ClientClass, target, chainId, permits, tls, genesis) {
  if (target && typeof target === 'object' && typeof target.transaction === 'function') return target;
  if (typeof target !== 'string' || !/^https?:\/\//.test(target)) throw new Error('an rpc endpoint must be an http or https url');
  if (!(await honoursFetch(ClientClass))) {
    throw new Error('the client core does not send its requests through the fetch function it is given, so they could not be held to the address policy and the endpoint was not used');
  }
  const pinned = typeof genesis === 'string' && /^[0-9a-f]{64}$/.test(genesis);
  if (genesis !== undefined && genesis !== null && !pinned) throw new Error('the genesis pinned for the network is not 64 lowercase hexadecimal characters');
  if (pinned && !(await holdsGenesis(ClientClass))) {
    throw new Error('the client core does not refuse a gateway that reports another genesis, so it could sign for another network and the endpoint was not used, install the client core this release pins');
  }
  const allow = typeof permits === 'function' ? permits : () => true;
  let client;
  try {
    const base = new URL(target).href.replace(/\/$/, '');
    const options = { fetch: guardedFetch(base, allow, tls || null) };
    if (chainId) options.expectedChainId = chainId;
    if (pinned) options.genesisHash = genesis;
    client = new ClientClass(base, options);
  } catch (e) {
    throw new Error('the client core refused the rpc endpoint', { cause: e });
  }
  return client;
}

function clientFor(target, chainId, permits, tls, genesis) {
  return clientWith(Client, target, chainId, permits, tls, genesis);
}

function clean(value, max) {
  return String(value).replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, ' ').slice(0, max || 200);
}

function isTransient(e) {
  if (e && typeof e.transient === 'boolean') return e.transient;
  if (e && e.code === 'QSTAMP_TRANSPORT') return isTransientCode(e.reason);
  return TRANSIENT.test(String((e && e.message) || e));
}

function failureCode(e) {
  return errorCode(e);
}

function jitter(delay) {
  const whole = Math.floor(delay);
  return whole + (whole > 0 ? crypto.randomInt(whole) : 0);
}

function backoffOf(delay, e) {
  const told = e && Number.isFinite(e.retryAfterMs) && e.retryAfterMs >= 0 ? Math.min(e.retryAfterMs, RETRY_AFTER_CAP_MS) : 0;
  return Math.max(jitter(delay), told);
}

async function read(fn, tries = 4) {
  let delay = FIRST_DELAY_MS;
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await D.within(fn());
    } catch (e) {
      if (attempt >= tries || !isTransient(e)) throw e;
      const wait = backoffOf(delay, e);
      if (wait >= D.left()) throw e;
      await D.pause(wait);
      delay = Math.min(delay * 2, READ_DELAY_CAP_MS);
    }
  }
}

function checkedTimeout(timeoutMs, fallback) {
  if (timeoutMs === undefined) return fallback;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 3600000) {
    throw new Error('the wait must be a whole number of milliseconds between 1000 and 3600000');
  }
  return timeoutMs;
}

function reportedFinal(tx) {
  return !!tx && (tx.status === 'finalised' || (tx.status === 'unverified' && tx.reportedStatus === 'finalised'));
}

async function waitFinal(client, txId, timeoutMs) {
  const ctl = D.narrowed(timeoutMs);
  return D.runWith(ctl, async () => {
    let delay = FIRST_DELAY_MS;
    for (;;) {
      let tx = null;
      let told = null;
      try {
        tx = await D.within(client.transaction(txId));
      } catch (e) {
        if (e && e.code === 'QSTAMP_TRANSPORT' && e.reason === 'aborted') throw e;
        if (D.stopped(ctl)) return null;
        if (!isTransient(e)) throw e;
        told = e;
      }
      if (reportedFinal(tx)) return tx;
      const wait = backoffOf(delay, told);
      if (wait >= D.left(ctl)) return null;
      await D.pause(wait);
      delay = Math.min(delay * 2, WAIT_DELAY_CAP_MS);
    }
  });
}

module.exports = { clientFor, clientWith, read, isTransient, checkedTimeout, waitFinal, reportedFinal, clean, failureCode, backoffOf, RETRY_AFTER_CAP_MS };
