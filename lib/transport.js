// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const http = require('http');
const https = require('https');
const dns = require('dns');
const { core } = require('@quantovainc/qcore');
const { classify } = require('./address');

const MAX_REPLY_BYTES = 8 * 1024 * 1024;
const TIMEOUT_MS = 20000;
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
  if (e.code === 'QSTAMP_TRANSPORT' && typeof e.reason === 'string') return e.reason;
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

function post(base, method, body, permits) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(base.replace(/\/$/, '') + '/v1/' + method);
    } catch (e) {
      reject(transportError('bad endpoint url', false));
      return;
    }
    if (url.protocol === 'http:' && !loopbackHost(url.hostname)) {
      reject(transportError('plaintext http refused', false));
      return;
    }
    const lib = url.protocol === 'https:' ? https : http;
    const payload = Buffer.from(body || '{}', 'utf8');
    const req = lib.request(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': payload.length, accept: 'application/json' },
      lookup: guardedLookup(permits),
      timeout: TIMEOUT_MS,
      agent: false,
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_REPLY_BYTES) {
          req.destroy(transportError('reply too large', false));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', (e) => reject(e));
    });
    req.on('timeout', () => req.destroy(transportError('timeout', true)));
    req.on('error', (e) => {
      const code = errorCode(e);
      reject(e && e.code === 'QSTAMP_TRANSPORT' ? e : transportError(code, isTransientCode(code)));
    });
    req.end(payload);
  });
}

async function call(base, method, body, strict, permits) {
  const { status, text } = await post(base, method, body, permits);
  if (status !== 200) {
    const code = 'http ' + status;
    throw transportError(code, isTransientCode(code));
  }
  if (strict) {
    try {
      core.checkGatewayJson(text);
    } catch (e) {
      throw transportError('malformed reply', false);
    }
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    throw transportError('malformed reply', false);
  }
}

function reader(base, permits) {
  const go = (method, body, strict) => call(base, method, body, strict, permits);
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
    validatorSet: (epoch) => go('get_validator_set', JSON.stringify({ epoch }), true),
    callRaw: go,
  };
}

module.exports = { reader, call, errorCode, isTransientCode, transportError, guardedLookup };
