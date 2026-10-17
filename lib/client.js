// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { Client } = require('@quantovainc/qcore');
const { guardedFetch, errorCode, isTransientCode } = require('./transport');
const D = require('./deadline');

const TRANSIENT = /non JSON|fetch failed|timed out|timeout|ECONNRESET|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN|ENOTFOUND|socket|network|status (429|5[0-9][0-9])/i;
const FIRST_DELAY_MS = 400;
const READ_DELAY_CAP_MS = 4000;
const WAIT_DELAY_CAP_MS = 8000;
const RETRY_AFTER_CAP_MS = 30000;

const PROBE_BASE = 'http://127.0.0.1:0';
const PROBE_REPLY = '{"chain_id":"qstamp-probe","genesis_hash":"00","head_height":0}';
const PROBE_MS = 2000;
const honoured = new WeakMap();

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
      const info = await D.within(client.nodeInfo(), { deadline: Date.now() + PROBE_MS, signal: undefined });
      return seen === 1 && !!info && info.chain_id === 'qstamp-probe';
    } catch (e) {
      return false;
    }
  })();
  honoured.set(ClientClass, verdict);
  return verdict;
}

async function clientWith(ClientClass, target, chainId, permits, tls) {
  if (target && typeof target === 'object' && typeof target.transaction === 'function') return target;
  if (typeof target !== 'string' || !/^https?:\/\//.test(target)) throw new Error('an rpc endpoint must be an http or https url');
  if (!(await honoursFetch(ClientClass))) {
    throw new Error('the client core does not send its requests through the fetch function it is given, so they could not be held to the address policy and the endpoint was not used');
  }
  const allow = typeof permits === 'function' ? permits : () => true;
  let client;
  try {
    const base = new URL(target).href.replace(/\/$/, '');
    const options = { fetch: guardedFetch(base, allow, tls || null) };
    if (chainId) options.expectedChainId = chainId;
    client = new ClientClass(base, options);
  } catch (e) {
    throw new Error('the client core refused the rpc endpoint', { cause: e });
  }
  return client;
}

function clientFor(target, chainId, permits, tls) {
  return clientWith(Client, target, chainId, permits, tls);
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
  return delay + Math.floor(Math.random() * delay);
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
      if (tx && tx.status === 'finalised') return tx;
      const wait = backoffOf(delay, told);
      if (wait >= D.left(ctl)) return null;
      await D.pause(wait);
      delay = Math.min(delay * 2, WAIT_DELAY_CAP_MS);
    }
  });
}

module.exports = { clientFor, clientWith, read, isTransient, checkedTimeout, waitFinal, clean, failureCode, backoffOf, RETRY_AFTER_CAP_MS };
