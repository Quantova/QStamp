// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const dns = require('dns');
const { clientFor, read, isTransient, clean, failureCode } = require('./client');
const { reader } = require('./transport');
const { network, officialEndpointsOf } = require('./networks');
const A = require('./address');

const MAX_ENDPOINTS = 8;
const DEFAULT_SLACK_MS = 30000;
const MIN_SLACK_MS = 5000;
const MAX_SLACK_MS = 900000;
const MONOTONIC_TOLERANCE_MS = 3000;
const HEAD_WALK = 16;
const LOOKUP_TIMEOUT_MS = 3000;
const RESERVED_TLDS = new Set(['example', 'test', 'invalid', 'localhost', 'local', 'internal']);
const ALWAYS_BLOCKED = new Set(['linklocal', 'unspecified', 'multicast', 'reserved', 'invalid']);
const lastSeen = new Map();

function urlKey(url) {
  const u = new URL(url);
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  const port = u.port ? ':' + u.port : '';
  return u.protocol + '//' + host + port + u.pathname.replace(/\/+$/, '');
}

function hostKey(url) {
  try {
    const host = A.hostOf(url);
    const ip = A.normaliseIp(host);
    if (ip) return A.classify(ip) === 'loopback' ? 'loopback' : 'ip:' + ip;
    if (A.isLoopbackName(host)) return 'loopback';
    return 'host:' + host;
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

function gather(opts) {
  const given = [];
  if (opts.clients !== undefined) {
    if (!Array.isArray(opts.clients)) throw new Error('clients is a list of rpc endpoints or clients');
    given.push(...opts.clients);
  }
  if (opts.client !== undefined) given.push(opts.client);
  if (opts.rpc !== undefined) given.push(...(Array.isArray(opts.rpc) ? opts.rpc : [opts.rpc]));
  return given.filter((t) => !(t === undefined || t === null || t === ''));
}

function syncKeys(target) {
  const keys = new Set();
  const base = typeof target === 'string' ? target : target && typeof target === 'object' && typeof target.base === 'string' ? target.base : null;
  if (base === null) {
    keys.add(target);
    return keys;
  }
  keys.add(hostKey(base));
  try {
    const host = A.hostOf(base);
    const domain = A.registrableDomain(host);
    if (domain) keys.add('domain:' + domain);
    for (const ip of A.embeddedIps(host)) keys.add('ip:' + ip);
  } catch (e) {
    keys.add('raw:' + base);
  }
  return keys;
}

function targetsOf(opts, net) {
  const given = gather(opts);
  if (given.length === 0 && net) given.push(...officialEndpointsOf(net).map((e) => e.url));
  const seen = new Set();
  const out = [];
  for (const t of given) {
    const keys = syncKeys(t);
    if ([...keys].some((k) => seen.has(k))) continue;
    for (const k of keys) seen.add(k);
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

function allowListOf(opts) {
  if (opts.endpointAllowList === undefined) return null;
  if (!Array.isArray(opts.endpointAllowList) || opts.endpointAllowList.some((v) => typeof v !== 'string' || v.length === 0 || v.length > 300)) {
    throw new Error('endpointAllowList is a list of host names or endpoint urls');
  }
  const hosts = new Set();
  const urls = new Set();
  for (const item of opts.endpointAllowList) {
    if (/^https?:\/\//i.test(item)) {
      try {
        urls.add(urlKey(item));
      } catch (e) {
        throw new Error('endpointAllowList holds an entry that is not a url');
      }
    } else {
      hosts.add(item.toLowerCase().replace(/\.$/, ''));
    }
  }
  return { hosts, urls };
}

function onAllowList(list, entry) {
  if (!list) return false;
  return list.hosts.has(entry.host) || list.urls.has(entry.key) || [...list.urls].some((u) => entry.key.startsWith(u + '/') || entry.key === u);
}

function officialMatch(net, key) {
  for (const e of officialEndpointsOf(net)) {
    try {
      if (urlKey(e.url) === key) return e;
    } catch (err) {
      continue;
    }
  }
  return null;
}

function describe(target, net) {
  if (typeof target === 'string') {
    let key;
    let host;
    try {
      const u = new URL(target);
      if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('protocol');
      if (u.username || u.password) throw new Error('credentials');
      key = urlKey(target);
      host = A.hostOf(target);
    } catch (e) {
      throw new Error('an rpc endpoint must be an http or https url without credentials');
    }
    const official = net ? officialMatch(net, key) : null;
    return { kind: 'url', target, label: target, key, host, official: !!official, operator: official ? official.operator : null, keys: new Set(), addresses: [] };
  }
  if (target && typeof target === 'object' && typeof target.transaction === 'function') {
    if (typeof target.base !== 'string' || !/^https?:\/\//i.test(target.base)) {
      throw new Error('a client object must name the endpoint it reads in base as an http or https url, so that endpoints run by one operator can be told apart');
    }
    let key;
    let host;
    try {
      key = urlKey(target.base);
      host = A.hostOf(target.base);
    } catch (e) {
      throw new Error('a client object must name the endpoint it reads in base as an http or https url, so that endpoints run by one operator can be told apart');
    }
    const operator = typeof target.operator === 'string' && target.operator.trim().length > 0 ? target.operator.trim() : null;
    return { kind: 'client', target, label: target.base, key: 'client:' + key, host, official: false, operator, keys: new Set(), addresses: [] };
  }
  throw new Error('an rpc endpoint must be an http or https url or a client object');
}

function lookupAll(host) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve([]), LOOKUP_TIMEOUT_MS);
    dns.lookup(host, { all: true, verbatim: true }, (err, addresses) => {
      clearTimeout(timer);
      resolve(err || !Array.isArray(addresses) ? [] : addresses.map((a) => a.address));
    });
  });
}

async function identify(entry, resolve) {
  const host = entry.host;
  const literal = A.normaliseIp(host);
  const domain = A.registrableDomain(host);
  if (entry.operator) entry.keys.add('operator:' + entry.operator.toLowerCase());
  if (domain) entry.keys.add('domain:' + domain);
  if (entry.official) return entry;
  if (literal) {
    entry.addresses.push(literal);
  } else if (A.isLoopbackName(host)) {
    entry.addresses.push('127.0.0.1');
  } else {
    for (const ip of A.embeddedIps(host)) entry.keys.add('ip:' + ip);
    const tld = host.split('.').pop();
    if (resolve && !RESERVED_TLDS.has(tld)) {
      for (const a of await lookupAll(host)) {
        const n = A.normaliseIp(a);
        if (n) entry.addresses.push(n);
      }
    }
  }
  for (const a of entry.addresses) entry.keys.add('ip:' + a);
  return entry;
}

function permitsFor(entry, opts, list) {
  if (entry.official) return () => true;
  const listed = onAllowList(list, entry);
  return (address) => {
    const n = A.normaliseIp(address);
    if (!n) return false;
    const cls = A.classify(n);
    if (cls === 'public') return true;
    if (ALWAYS_BLOCKED.has(cls)) return false;
    if (cls === 'loopback') return opts.allowLoopback === true;
    if (cls === 'private') return listed;
    return false;
  };
}

function policyProblem(entry, opts, list) {
  if (entry.official) return null;
  if (list && !onAllowList(list, entry)) return 'the endpoint ' + clean(entry.label, 120) + ' is not on the endpoint allow list';
  if (entry.kind !== 'url') return null;
  if (A.isLoopbackName(entry.host) && opts.allowLoopback !== true) {
    return 'the endpoint ' + clean(entry.label, 120) + ' is a loopback address, which is refused unless allowLoopback is true';
  }
  const permits = permitsFor(entry, opts, list);
  for (const a of entry.addresses) {
    if (!permits(a)) {
      const cls = A.classify(a);
      if (cls === 'loopback') return 'the endpoint ' + clean(entry.label, 120) + ' is a loopback address, which is refused unless allowLoopback is true';
      if (cls === 'private') return 'the endpoint ' + clean(entry.label, 120) + ' is a private network address, which is refused unless the endpoint is on the allow list';
      return 'the endpoint ' + clean(entry.label, 120) + ' resolves to a ' + cls + ' address, which is always refused';
    }
  }
  return null;
}

function groupsOf(entries, keysOf) {
  const parent = entries.map((_, i) => i);
  const find = (i) => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  const owner = new Map();
  entries.forEach((e, i) => {
    for (const k of keysOf(e)) {
      if (owner.has(k)) parent[find(i)] = find(owner.get(k));
      else owner.set(k, i);
    }
  });
  const groups = new Map();
  entries.forEach((e, i) => {
    const root = find(i);
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root).push(e);
  });
  return [...groups.values()];
}

function independentGroups(entries) {
  return groupsOf(entries, (e) => e.keys);
}

function officialGroups(entries) {
  return groupsOf(entries.filter((e) => e.official), (e) => [...e.keys].filter((k) => k.startsWith('operator:') || k.startsWith('domain:')));
}

async function endpointsFor(opts, net, purpose) {
  const list = allowListOf(opts);
  const given = gather(opts);
  const defaults = given.length === 0;
  const raw = defaults ? officialEndpointsOf(net).map((e) => e.url) : given;
  const entries = [];
  const seen = new Set();
  for (const t of raw) {
    const entry = describe(t, net);
    if (seen.has(entry.key)) continue;
    seen.add(entry.key);
    entries.push(entry);
  }
  if (entries.length > MAX_ENDPOINTS) throw new Error('at most ' + MAX_ENDPOINTS + ' endpoints may be consulted');
  const custom = entries.filter((e) => !e.official);
  if (custom.length > 0 && purpose !== 'stamp' && opts.trustCustomEndpoints !== true) {
    return {
      entries,
      custom: true,
      refused: 'endpoints other than the official ones of this network were given (' + custom.map((e) => clean(e.label, 80)).join(', ') + '), they are consulted only when trustCustomEndpoints is true and a result reached through them is never reported valid',
    };
  }
  await Promise.all(entries.map((e) => identify(e, true)));
  for (const e of entries) {
    const problem = policyProblem(e, opts, list);
    if (problem) return { entries, custom: custom.length > 0, refused: problem };
    e.permits = permitsFor(e, opts, list);
  }
  return { entries, custom: custom.length > 0, refused: null, groups: independentGroups(entries) };
}

function clientOf(entry, chainId) {
  if (entry.kind === 'client') return entry.target;
  return clientFor(entry.target, chainId, entry.permits);
}

function readerOf(entry) {
  if (entry.kind === 'client') return entry.target;
  return reader(entry.target, entry.permits || (() => true));
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
    throw clockError('the endpoint ' + clean(label, 120) + ' could not answer (' + failureCode(e) + ')', isTransient(e));
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
      if (isTransient(e)) throw clockError('the endpoint ' + clean(label, 120) + ' could not answer (' + failureCode(e) + ')', true);
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

function trustOf(entries, groups) {
  if (entries.some((e) => !e.official)) return 'custom-endpoints';
  const official = officialGroups(entries);
  if (official.length >= 2 && groups.length >= 2) return 'official-quorum';
  return 'single-endpoint';
}

async function chainTimeWith(options, internal) {
  const opts = options || {};
  const net = network(opts.network === undefined ? 'testnet' : opts.network);
  const slack = slackOf(opts);
  let plan;
  try {
    plan = await endpointsFor(opts, net, internal && internal.allowCustom ? 'stamp' : 'time');
  } catch (e) {
    throw clockError(clean(e.message, 300));
  }
  if (plan.refused) throw clockError(plan.refused);
  if (plan.entries.length === 0) throw clockError('no rpc endpoint is known for this chain');
  if (plan.groups.length < 2 && opts.trustSingleEndpoint !== true) {
    throw clockError('the endpoints given are not run independently of each other, so a dishonest operator could set the chain time alone, list at least two endpoints run by different operators or set trustSingleEndpoint to true to rely on one');
  }
  const readings = [];
  for (const e of plan.entries) readings.push(await headTime(readerOf(e), net, e.label));
  const hostMs = Date.now();
  const lo = Math.min(...readings.map((r) => r.ms));
  const hi = Math.max(...readings.map((r) => r.ms));
  if (hi - lo > slack) throw clockError('the endpoints disagree about the time of the chain head by more than ' + Math.round(slack / 1000) + ' seconds');
  if (lo < hostMs - slack) {
    throw clockError('an endpoint reports a finalised head at ' + new Date(lo).toISOString() + ', more than ' + Math.round(slack / 1000) + ' seconds behind the local clock, so it is stale or wrong');
  }
  const last = lastSeen.get(net.genesis);
  if (last !== undefined && hi < last - MONOTONIC_TOLERANCE_MS) {
    throw clockError('the endpoints report a chain time earlier than the ' + new Date(last).toISOString() + ' seen before, so they are stale or wrong');
  }
  if (last === undefined || hi > last) lastSeen.set(net.genesis, hi);
  return {
    chainMs: hi,
    hostMs,
    early: Math.min(hi, hostMs),
    late: Math.max(hi, hostMs),
    height: Math.min(...readings.map((r) => r.height)),
    endpoints: readings.map((r) => r.label),
    officialEndpoints: plan.entries.every((e) => e.official),
    trust: trustOf(plan.entries, plan.groups),
  };
}

function chainTime(options) {
  return chainTimeWith(options, null);
}

module.exports = {
  targetsOf,
  quorumProblem,
  keyOf,
  labelOf,
  chainTime,
  chainTimeWith,
  endpointsFor,
  independentGroups,
  officialGroups,
  clientOf,
  readerOf,
  describe,
  identify,
  MAX_ENDPOINTS,
  DEFAULT_SLACK_MS,
};
