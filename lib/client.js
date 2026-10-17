// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { Client } = require('@quantovainc/qcore');
const { call, errorCode, isTransientCode } = require('./transport');

const TRANSIENT = /non JSON|fetch failed|timed out|timeout|ECONNRESET|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN|ENOTFOUND|socket|network|status (429|5[0-9][0-9])/i;

function clientFor(target, chainId, permits) {
  if (target && typeof target === 'object' && typeof target.transaction === 'function') return target;
  if (typeof target !== 'string' || !/^https?:\/\//.test(target)) throw new Error('an rpc endpoint must be an http or https url');
  const client = new Client(target, chainId ? { expectedChainId: chainId } : {});
  if (typeof client._call === 'function') {
    const base = client.base;
    const allow = typeof permits === 'function' ? permits : () => true;
    client._call = (method, body, strict) => call(base, method, body, strict, allow);
  }
  return client;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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

async function read(fn, tries = 4) {
  let delay = 400;
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await fn();
    } catch (e) {
      if (attempt >= tries || !isTransient(e)) throw e;
      await sleep(delay + Math.floor(Math.random() * delay));
      delay = Math.min(delay * 2, 4000);
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
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    let tx = null;
    try {
      tx = await client.transaction(txId);
    } catch (e) {
      tx = null;
    }
    if (tx && tx.status === 'finalised') return tx;
    if (Date.now() > deadline) return null;
    await sleep(400);
  }
}

module.exports = { clientFor, read, isTransient, checkedTimeout, waitFinal, clean, failureCode };
