// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const NETWORKS = Object.freeze({
  testnet: Object.freeze({
    name: 'testnet',
    rpc: 'https://rpc-testnet.quantova.org',
    chainId: 'Q-test-net-1',
    genesis: 'ca91e093bb8de33e90db52d7c89876597d14760703793ea7211929e73e613062',
    contract: 'Q1D6TZFRL203P3DFAFVUPZUHGUCM4EWGH6063XNS42VA5235RNQWXS7FXEWX',
  }),
});

function network(name) {
  if (typeof name !== 'string' || !Object.prototype.hasOwnProperty.call(NETWORKS, name)) {
    throw new Error('unknown network ' + String(name));
  }
  return NETWORKS[name];
}

module.exports = { NETWORKS, network };
