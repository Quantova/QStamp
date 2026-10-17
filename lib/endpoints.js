// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { clientFor, read, isTransient, clean } = require('./client');
const { network } = require('./networks');

const MAX_ENDPOINTS = 8;
const DEFAULT_SLACK_MS = 120000;
const MIN_SLACK_MS = 5000;
const MAX_SLACK_MS = 900000;
const MONOTONIC_TOLERANCE_MS = 3000;
const HEAD_WALK = 16;
const lastSeen = new Map();

function isLoopback(host) {
  return host === 'localhost' || host === '[::1]' || host === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

function hostKey(url) {
  try {
    const host = new URL(url).hostname.toLowerCase().replace(/\.$/, '');
    return isLoopback(host) ? 'loopback' : 'host:' + host;
  } catch (e) {
    return 'raw:' + url;
  }
}

function keyOf(target) {
  if (typeof target === 'string') return hostKey(target);
  if (target && typeof target === 'object' && typeof target.base === 'string') return hostKey(target.base);
  return target;
}

function labelOf(target) {
  if (typeof target === 'string') return target;
  if (target && typeof target === 'object' && typeof target.base === 'string') return target.base;
  return 'custom client';
}

function targetsOf(opts, net) {
  const given = [];
  if (opts.clients !== undefined) {
    if (!Array.isArray(opts.clients)) throw new Error('clients is a list of rpc endpoints or clients');
    given.push(...opts.clients);
  }
  if (opts.client !== undefined) given.push(opts.client);
  if (opts.rpc !== undefined) given.push(...(Array.isArray(opts.rpc) ? opts.rpc : [opts.rpc]));
  if (given.length === 0 && net) given.push(...(Array.isArray(net.rpcs) ? net.rpcs : [net.rpc]));
  const keys = new Set();
  const out = [];
  for (const t of given) {
    if (t === undefined || t === null || t === '') continue;
    const key = keyOf(t);
    if (keys.has(key)) continue;
    keys.add(key);
    out.push(t);
  }
  if (out.length > MAX_ENDPOINTS) throw new Error('at most ' + MAX_ENDPOINTS + ' independent endpoints may be consulted');
  return out;
}

function quorumProblem(targets, opts) {
  if (targets.length === 0) return 'no rpc endpoint is known for this chain';
  if (targets.length >= 2) return null;
  if (opts.trustSingleEndpoint === true) return null;
  return 'only one independent endpoint was given, so a dishonest endpoint could invent the chain data alone, list at least two endpoints run by different operators in clients or set trustSingleEndpoint to true to rely on one';
}

function slackOf(opts) {
  if (opts.clockSlackMs === undefined) return DEFAULT_SLACK_MS;
  const v = opts.clockSlackMs;
  if (!Number.isSafeInteger(v) || v < MIN_SLACK_MS || v > MAX_SLACK_MS) throw new Error('clockSlackMs is a whole number of milliseconds from ' + MIN_SLACK_MS + ' to ' + MAX_SLACK_MS);
  return v;
}

function clockError(message, transport) {
  const e = new Error(message);
  e.code = 'QSTAMP_CHAIN_TIME';
  e.transport = !!transport;
  return e;
}

async function headTime(client, net, label) {
  let info;
  try {
    info = await read(() => client.nodeInfo());
  } catch (e) {
    throw clockError('the endpoint ' + clean(label, 120) + ' could not answer (' + clean((e && e.message) || e, 120) + ')', isTransient(e));
  }
  if (!info || info.chain_id !== net.chainId || info.genesis_hash !== net.genesis) {
    throw clockError('the endpoint ' + clean(label, 120) + ' does not serve the ' + net.name + ' chain');
  }
  const head = info.head_height;
  if (!Number.isSafeInteger(head) || head < 0) throw clockError('the endpoint ' + clean(label, 120) + ' reported no valid head height');
  for (let h = head; h >= 0 && h > head - HEAD_WALK; h -= 1) {
    let block;
    try {
      block = await read(() => client.block(h));
    } catch (e) {
      if (isTransient(e)) throw clockError('the endpoint ' + clean(label, 120) + ' could not answer (' + clean((e && e.message) || e, 120) + ')', true);
      continue;
    }
    if (!block) continue;
    if (block.height !== h || !Number.isSafeInteger(block.time) || block.time <= 0) {
      throw clockError('the endpoint ' + clean(label, 120) + ' reported a malformed block');
    }
    return { label, height: h, ms: block.time * 1000 };
  }
  throw clockError('the endpoint ' + clean(label, 120) + ' reported no finalised block near its head', true);
}

async function chainTime(options) {
  const opts = options || {};
  const net = network(opts.network === undefined ? 'testnet' : opts.network);
  const slack = slackOf(opts);
  const targets = targetsOf(opts, net);
  const problem = quorumProblem(targets, opts);
  if (problem) throw clockError(problem);
  const readings = [];
  for (const t of targets) readings.push(await headTime(clientFor(t, net.chainId), net, labelOf(t)));
  const hostMs = Date.now();
  const lo = Math.min(...readings.map((r) => r.ms));
  const hi = Math.max(...readings.map((r) => r.ms));
  if (hi - lo > slack) throw clockError('the endpoints disagree about the time of the chain head by more than ' + Math.round(slack / 1000) + ' seconds');
  if (lo < hostMs - slack) {
    throw clockError('an endpoint reports a finalised head at ' + new Date(lo).toISOString() + ', more than ' + Math.round(slack / 1000) + ' seconds behind the local clock, so it is stale or wrong');
  }
  const last = lastSeen.get(net.genesis);
  if (last !== undefined && lo < last - MONOTONIC_TOLERANCE_MS) {
    throw clockError('an endpoint reports a chain time earlier than the ' + new Date(last).toISOString() + ' seen before, so it is stale or wrong');
  }
  if (last === undefined || lo > last) lastSeen.set(net.genesis, lo);
  return {
    chainMs: lo,
    hostMs,
    early: Math.min(lo, hostMs),
    late: Math.max(hi, hostMs),
    height: Math.min(...readings.map((r) => r.height)),
    endpoints: readings.map((r) => r.label),
  };
}

module.exports = { targetsOf, quorumProblem, keyOf, labelOf, chainTime, MAX_ENDPOINTS };
