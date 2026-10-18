// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const A = require('./address');
const { decode } = require('./bech32m');
const { tlsSettings } = require('./transport');
const { clean } = require('./client');
const { parseRoster } = require('./finality');

const ENDPOINTS_MAX = 8;
const RATE_MAX = 1000;
const SLACK_MAX = 1000000;
const ENTRY_KEYS = new Set(['url', 'operator', 'ca', 'cert', 'key', 'insecure']);

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

const NETWORKS = deepFreeze({
  testnet: {
    name: 'testnet',
    rpc: 'https://rpc-testnet.quantova.org',
    rpcs: [
      { url: 'https://rpc-testnet.quantova.org', operator: 'Quantova Inc' },
    ],
    chainId: 'Q-test-net-01',
    genesis: 'ca91e093bb8de33e90db52d7c89876597d14760703793ea7211929e73e613062',
    contract: 'Q1D6TZFRL203P3DFAFVUPZUHGUCM4EWGH6063XNS42VA5235RNQWXS7FXEWX',
    genesisTime: 1791082813,
    blocks: { minPerSecond: 1, maxPerSecond: 6, stallSeconds: 86400, slack: 240 },
    finality: { genesis: 'ca91e093bb8de33e90db52d7c89876597d14760703793ea7211929e73e613062', checkpoint: null, epochBlocks: null, rosters: {} },
  },
});

function network(name) {
  if (typeof name !== 'string' || !Object.prototype.hasOwnProperty.call(NETWORKS, name)) {
    throw new Error('unknown network ' + String(name));
  }
  return NETWORKS[name];
}

function officialEndpointsOf(net) {
  if (!net) return [];
  if (Array.isArray(net.rpcs) && net.rpcs.length > 0) {
    return net.rpcs.filter((e) => e && typeof e.url === 'string' && typeof e.operator === 'string' && e.operator.length > 0);
  }
  return typeof net.rpc === 'string' ? [{ url: net.rpc, operator: net.name }] : [];
}

function rosterPinned(finality) {
  return !!finality && !!finality.rosters && typeof finality.rosters === 'object' &&
    Object.keys(finality.rosters).some((k) => Array.isArray(finality.rosters[k]) && finality.rosters[k].length > 0);
}

function requiresFinality(net) {
  if (!net) return false;
  if (typeof net.requireFinality === 'boolean') return net.requireFinality;
  return rosterPinned(net.finality);
}

function loopbackHost(host) {
  if (A.isLoopbackName(host)) return true;
  return A.normaliseIp(host) !== null && A.classify(host) === 'loopback';
}

function hostIdentity(host) {
  const ip = A.normaliseIp(host);
  if (ip) return ['ip:' + ip];
  if (A.isLoopbackName(host)) return A.LOOPBACK_ADDRESSES.map((a) => 'ip:' + a);
  return ['host:' + host].concat(A.embeddedIps(host).map((a) => 'ip:' + a));
}

function checkBounds(net) {
  if (!Number.isSafeInteger(net.genesisTime) || net.genesisTime < 0) {
    throw new Error('the network must give genesisTime, the time of its first block in whole seconds since 1970, so that anchor times can be checked');
  }
  const b = net.blocks;
  const rate = (v) => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= RATE_MAX;
  const whole = (v, max) => Number.isSafeInteger(v) && v >= 0 && v <= max;
  if (!b || typeof b !== 'object' || !rate(b.minPerSecond) || !rate(b.maxPerSecond) || b.maxPerSecond <= 0 ||
    b.minPerSecond > b.maxPerSecond || !whole(b.stallSeconds, Number.MAX_SAFE_INTEGER) || !whole(b.slack, SLACK_MAX)) {
    throw new Error('the network must give blocks with minPerSecond, maxPerSecond, stallSeconds and slack, the bounds that let an anchor height be checked against its time');
  }
}

function checkEndpoint(e, opts) {
  if (!e || typeof e !== 'object' || Array.isArray(e)) throw new Error('each network endpoint is an object with its url and the operator that runs it');
  for (const k of Object.keys(e)) {
    if (!ENTRY_KEYS.has(k)) throw new Error('a network endpoint holds only url, operator, ca, cert, key and insecure');
  }
  if (typeof e.operator !== 'string' || e.operator.trim().length === 0 || e.operator.length > 80) throw new Error('each network endpoint names the operator that runs it');
  let u;
  let host;
  try {
    u = new URL(e.url);
    host = A.hostOf(e.url);
  } catch (err) {
    throw new Error('a network endpoint must be an http or https url without credentials');
  }
  if ((u.protocol !== 'https:' && u.protocol !== 'http:') || u.username || u.password) {
    throw new Error('a network endpoint must be an http or https url without credentials');
  }
  if (e.insecure !== undefined && e.insecure !== true) throw new Error('insecure on a network endpoint is either left out or set to true');
  if (e.insecure === true && u.protocol !== 'http:') throw new Error('insecure applies only to a network endpoint reached over plain http');
  if (u.protocol === 'http:' && e.insecure !== true) {
    if (!loopbackHost(host)) {
      throw new Error('the network endpoint ' + clean(e.url, 120) + ' uses plain http, which is refused unless the endpoint is marked insecure for an air gapped network');
    }
    if (opts.allowLoopback !== true) {
      throw new Error('the network endpoint ' + clean(e.url, 120) + ' uses plain http on a loopback address, which is refused unless allowLoopback is true');
    }
  }
  if (u.protocol === 'http:' && (e.ca !== undefined || e.cert !== undefined || e.key !== undefined)) {
    throw new Error('the network endpoint ' + clean(e.url, 120) + ' gives TLS settings but uses plain http');
  }
  tlsSettings(e);
  return { host, operator: e.operator.trim().toLowerCase() };
}

function checkEndpoints(net, opts) {
  if (!Array.isArray(net.rpcs) || net.rpcs.length === 0 || net.rpcs.length > ENDPOINTS_MAX) {
    throw new Error('the network must list 1 to ' + ENDPOINTS_MAX + ' endpoints in rpcs, each with its url and the operator that runs it');
  }
  const owners = new Map();
  for (const e of net.rpcs) {
    const { host, operator } = checkEndpoint(e, opts);
    for (const id of hostIdentity(host)) {
      if (owners.has(id) && owners.get(id) !== operator) {
        throw new Error('the network lists the host ' + clean(host, 80) + ' under two operators, so one host could pass for two independent endpoints');
      }
      owners.set(id, operator);
    }
  }
}

function checkFinality(net) {
  if (net.requireFinality !== undefined && typeof net.requireFinality !== 'boolean') throw new Error('requireFinality is either true or false');
  const f = net.finality;
  if (f === undefined) return;
  if (!f || typeof f !== 'object' || Array.isArray(f)) throw new Error('the network finality is given as genesis, checkpoint, epochBlocks and rosters');
  if (f.genesis !== undefined && f.genesis !== null && f.genesis !== net.genesis) {
    throw new Error('the network finality is pinned to a genesis other than the genesis of the network, and a finality proof counts only on the genesis its rosters were pinned for');
  }
  const c = f.checkpoint;
  if (c !== undefined && c !== null && (!c || typeof c !== 'object' || Array.isArray(c) || !Number.isSafeInteger(c.height) || c.height < 0 ||
    typeof c.hash !== 'string' || !/^[0-9a-f]{64}$/.test(c.hash))) {
    throw new Error('the network checkpoint gives the height of a certified block and its header hash as 64 lowercase hexadecimal characters');
  }
  if (f.epochBlocks !== undefined && f.epochBlocks !== null && (!Number.isSafeInteger(f.epochBlocks) || f.epochBlocks < 1)) {
    throw new Error('the network epochBlocks is a positive whole number');
  }
  if (f.rosters !== undefined && (!f.rosters || typeof f.rosters !== 'object' || Array.isArray(f.rosters))) {
    throw new Error('the network rosters map each epoch to its validator roster');
  }
  for (const [epoch, roster] of Object.entries(f.rosters || {})) {
    if (!/^(0|[1-9][0-9]{0,15})$/.test(epoch) || !Number.isSafeInteger(Number(epoch))) throw new Error('the network rosters are keyed by whole epoch numbers');
    if (!Array.isArray(roster)) throw new Error('the network roster of epoch ' + epoch + ' is not a list of validators');
    if (roster.length === 0) continue;
    try {
      parseRoster(roster);
    } catch (e) {
      throw new Error('the network roster of epoch ' + epoch + ' is refused, ' + e.message + ', and every validator names its id, stake, attest_pk, root and root_slots as get_validator_set serves them');
    }
  }
}

function checkNetwork(net, options) {
  const opts = options || {};
  if (!net || typeof net !== 'object') throw new Error('a network is given as an object');
  if (typeof net.name !== 'string' || net.name.length === 0 || net.name.length > 64) throw new Error('the network must give its name');
  if (typeof net.chainId !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(net.chainId)) throw new Error('the network chain id is malformed');
  if (typeof net.genesis !== 'string' || !/^[0-9a-f]{64}$/.test(net.genesis)) throw new Error('the network genesis must be 64 lowercase hexadecimal characters');
  try {
    if (typeof net.contract !== 'string') throw new Error('type');
    decode(net.contract, 'Q', 32);
  } catch (e) {
    throw new Error('the network contract is not a Quantova address');
  }
  checkBounds(net);
  checkEndpoints(net, opts);
  checkFinality(net);
  return net;
}

module.exports = { NETWORKS, network, officialEndpointsOf, deepFreeze, checkNetwork, requiresFinality, rosterPinned, hostIdentity };
