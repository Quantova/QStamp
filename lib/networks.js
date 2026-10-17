// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

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
    chainId: 'Q-test-net-1',
    genesis: 'ca91e093bb8de33e90db52d7c89876597d14760703793ea7211929e73e613062',
    contract: 'Q1D6TZFRL203P3DFAFVUPZUHGUCM4EWGH6063XNS42VA5235RNQWXS7FXEWX',
    genesisTime: 1791082813,
    blocks: { minPerSecond: 1, maxPerSecond: 20, stallSeconds: 86400, slack: 240 },
    finality: { epochBlocks: null, rosters: {} },
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

module.exports = { NETWORKS, network, officialEndpointsOf, deepFreeze };
