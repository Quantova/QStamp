// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const http = require('http');
const https = require('https');
const dns = require('dns');
const { isIP } = require('net');
const { core } = require('@quantovainc/qcore');
const { classify } = require('./address');
const { current, stopped, left, signalsOf, deadlinePassed, aborted } = require('./deadline');

const MAX_REPLY_BYTES = 8 * 1024 * 1024;
const TIMEOUT_MS = 20000;
const REQUEST_MS = 30000;
const MAX_TLS_BYTES = 1024 * 1024;
const SAFE_REASON = /^[a-z][a-z0-9 ]{0,39}$/;
const NETWORK_CODES = {
  ETIMEDOUT: 'timeout',
  ECONNRESET: 'connection reset',
  ECONNREFUSED: 'connection refused',
  EHOSTUNREACH: 'unreachable',
  ENETUNREACH: 'unreachable',
  EAI_AGAIN: 'name lookup failed',
  ENOTFOUND: 'name not found',
  EPIPE: 'connection reset',
  CERT_HAS_EXPIRED: 'certificate rejected',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'certificate rejected',
  SELF_SIGNED_CERT_IN_CHAIN: 'certificate rejected',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'certificate rejected',
  ERR_TLS_CERT_ALTNAME_INVALID: 'certificate rejected',
  UNABLE_TO_GET_ISSUER_CERT: 'certificate rejected',
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'certificate rejected',
  CERT_NOT_YET_VALID: 'certificate rejected',
  CERT_UNTRUSTED: 'certificate rejected',
  ERR_SSL_UNSUPPORTED_PROTOCOL: 'tls refused',
  ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION: 'tls refused',
  ERR_SSL_WRONG_VERSION_NUMBER: 'tls refused',
};
const TRANSIENT_CODES = new Set(['timeout', 'connection reset', 'connection refused', 'unreachable', 'name lookup failed']);

function transportError(code, transient) {
  const e = new Error(code);
  e.code = 'QSTAMP_TRANSPORT';
  e.reason = code;
  e.transient = !!transient;
  return e;
}

function errorCode(e) {
  if (!e) return 'error';
  if (e.code === 'QSTAMP_TRANSPORT') return typeof e.reason === 'string' && SAFE_REASON.test(e.reason) ? e.reason : 'error';
  if (e.code === 'QSTAMP_ADDRESS') return 'address refused';
  if (typeof e.code === 'string' && Object.prototype.hasOwnProperty.call(NETWORK_CODES, e.code)) return NETWORK_CODES[e.code];
  const text = String(e.message || e);
  if (e.name === 'AbortError' || /timed out|timeout/i.test(text)) return 'timeout';
  const status = /\bstatus (\d{3})\b/.exec(text);
  if (status) return 'http ' + status[1];
  if (/non JSON/i.test(text)) return 'malformed reply';
  if (/fetch failed|socket|ECONNRESET|ECONNREFUSED|ENOTFOUND|EAI_AGAIN|ETIMEDOUT|network/i.test(text)) return 'unreachable';
  return 'error';
}

function isTransientCode(code) {
  return TRANSIENT_CODES.has(code) || /^http (429|5\d\d)$/.test(code);
}

function guardedLookup(permits) {
  return (hostname, options, callback) => {
    const cb = typeof options === 'function' ? options : callback;
    const wantAll = !!(options && typeof options === 'object' && options.all);
    dns.lookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
      if (err) return cb(err);
      if (!Array.isArray(addresses) || addresses.length === 0) return cb(transportError('name not found', false));
      if (addresses.some((a) => !permits(a.address))) {
        const refused = new Error('address refused');
        refused.code = 'QSTAMP_ADDRESS';
        return cb(refused);
      }
      if (wantAll) return cb(null, addresses);
      return cb(null, addresses[0].address, addresses[0].family);
    });
  };
}

function loopbackHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  return classify(host) === 'loopback';
}

function retryAfterMs(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 64) return undefined;
  if (/^[0-9]{1,9}$/.test(value)) return Number(value) * 1000;
  const at = Date.parse(value);
  if (!Number.isFinite(at)) return undefined;
  return Math.max(0, at - Date.now());
}

function tlsBytes(value, what) {
  if (typeof value === 'string' && value.length > 0 && value.length <= MAX_TLS_BYTES) return value;
  if (Buffer.isBuffer(value) && value.length > 0 && value.length <= MAX_TLS_BYTES) return value;
  throw new Error('the TLS ' + what + ' of an endpoint must be a string or a Buffer');
}

function tlsSettings(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const out = {};
  if (entry.ca !== undefined) out.ca = tlsBytes(entry.ca, 'ca');
  if (entry.cert !== undefined) out.cert = tlsBytes(entry.cert, 'cert');
  if (entry.key !== undefined) out.key = tlsBytes(entry.key, 'key');
  if ((out.cert === undefined) !== (out.key === undefined)) throw new Error('the TLS cert and key of an endpoint must be given together');
  return Object.keys(out).length ? Object.freeze(out) : null;
}

function post(base, method, body, permits, tls, coreSignal) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(base.replace(/\/$/, '') + '/v1/' + method);
    } catch (e) {
      reject(transportError('bad endpoint url', false));
      return;
    }
    if (url.protocol === 'http:' && !loopbackHost(url.hostname) && !(tls && tls.insecure === true)) {
      reject(transportError('plaintext http refused', false));
      return;
    }
    const literal = url.hostname.replace(/^\[|\]$/g, '');
    if (isIP(literal) && !permits(literal)) {
      reject(transportError('address refused', false));
      return;
    }
    const ctl = current();
    const stop = stopped(ctl);
    if (stop) {
      reject(stop);
      return;
    }
    const secure = url.protocol === 'https:';
    const lib = secure ? https : http;
    const payload = Buffer.from(body || '{}', 'utf8');
    const remaining = left(ctl);
    const callerBound = remaining <= REQUEST_MS;
    const options = {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': payload.length, accept: 'application/json' },
      lookup: guardedLookup(permits),
      timeout: TIMEOUT_MS,
      agent: false,
    };
    if (secure) {
      options.rejectUnauthorized = true;
      options.minVersion = 'TLSv1.2';
      if (tls && tls.ca !== undefined) options.ca = tls.ca;
      if (tls && tls.cert !== undefined) options.cert = tls.cert;
      if (tls && tls.key !== undefined) options.key = tls.key;
    }
    let failure = null;
    let settled = false;
    let timer = null;
    const signals = signalsOf(ctl);
    const onAbort = () => fail(aborted());
    const onCoreAbort = () => fail(transportError('timeout', true));
    const finish = (fn, v) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      for (const s of signals) s.removeEventListener('abort', onAbort);
      if (coreSignal) coreSignal.removeEventListener('abort', onCoreAbort);
      fn(v);
    };
    const req = lib.request(url, options, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_REPLY_BYTES) {
          fail(transportError('reply too large', false));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        if (failure) return;
        finish(resolve, { status: res.statusCode, text: Buffer.concat(chunks).toString('utf8'), retryAfter: res.headers['retry-after'] });
      });
      res.on('error', (e) => finish(reject, failure || mapped(e)));
      res.on('close', () => {
        if (!res.complete) finish(reject, failure || transportError('connection reset', true));
      });
    });
    function fail(e) {
      if (settled || failure) return;
      failure = e;
      req.destroy(e);
      finish(reject, e);
    }
    timer = setTimeout(() => fail(callerBound ? deadlinePassed() : transportError('slow reply', false)), Math.max(1, Math.min(REQUEST_MS, remaining)));
    for (const s of signals) s.addEventListener('abort', onAbort, { once: true });
    if (coreSignal) {
      if (coreSignal.aborted) onCoreAbort();
      else coreSignal.addEventListener('abort', onCoreAbort, { once: true });
    }
    req.on('timeout', () => fail(transportError('timeout', true)));
    req.on('error', (e) => finish(reject, failure || mapped(e)));
    req.end(payload);
  });
}

function mapped(e) {
  if (e && e.code === 'QSTAMP_TRANSPORT') return e;
  const code = errorCode(e);
  return transportError(code, isTransientCode(code));
}

async function exchange(base, method, body, permits, tls, coreSignal) {
  const { status, text, retryAfter } = await post(base, method, body, permits, tls, coreSignal);
  if (status !== 200) {
    const code = 'http ' + status;
    const e = transportError(code, isTransientCode(code));
    const wait = status === 429 || status === 503 ? retryAfterMs(retryAfter) : undefined;
    if (wait !== undefined) e.retryAfterMs = wait;
    throw e;
  }
  try {
    core.checkGatewayJson(text);
    JSON.parse(text);
  } catch (e) {
    throw transportError('malformed reply', false);
  }
  return text;
}

async function call(base, method, body, strict, permits, tls) {
  return JSON.parse(await exchange(base, method, body, permits, tls, null));
}

function isSignal(value) {
  return !!value && typeof value === 'object' && typeof value.aborted === 'boolean' && typeof value.addEventListener === 'function';
}

function guardedFetch(base, permits, tls) {
  const prefix = base.replace(/\/$/, '') + '/v1/';
  return async (url, init) => {
    const target = String(url);
    const method = target.startsWith(prefix) ? target.slice(prefix.length) : '';
    if (!/^[a-z_]{1,64}$/.test(method)) throw transportError('bad endpoint url', false);
    const opts = init || {};
    if (opts.method !== undefined && opts.method !== 'POST') throw transportError('bad request', false);
    if (opts.body !== undefined && typeof opts.body !== 'string') throw transportError('bad request', false);
    const text = await exchange(base, method, opts.body, permits, tls, isSignal(opts.signal) ? opts.signal : null);
    return new Response(text, { status: 200, headers: { 'content-type': 'application/json' } });
  };
}

function reader(base, permits, tls) {
  const go = (method, body, strict) => call(base, method, body, strict, permits, tls);
  const u64 = (v) => BigInt(v);
  return {
    base,
    nodeInfo: () => go('node_info', '{}', true),
    transaction: (txId) => go('get_transaction', core.transaction_body(txId)),
    events: (height) => go('get_events', core.eventsBody(u64(height))),
    block: (height) => go('get_block', core.block_by_height_body(u64(height))),
    storageAt: (contract, keys) => go('get_storage_at', JSON.stringify({ address: contract, keys }), true),
    finality: (height) => go('get_finality', JSON.stringify({ height }), true),
    eventProof: (height, index) => go('get_event_proof', JSON.stringify({ height, index }), true),
    transactionProof: (txId) => go('get_transaction_proof', JSON.stringify({ tx_id: txId }), true),
    validatorSet: (epoch) => go('get_validator_set', JSON.stringify({ epoch }), true),
    callRaw: go,
  };
}

module.exports = { reader, call, guardedFetch, errorCode, isTransientCode, transportError, guardedLookup, tlsSettings, retryAfterMs, REQUEST_MS };
