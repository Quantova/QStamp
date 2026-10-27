// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const https = require('https');
const { NETWORKS, officialEndpointsOf } = require('../lib/networks');

function post(base, method, body) {
  const url = new URL(base.replace(/\/+$/, '') + '/v1/' + method);
  const payload = Buffer.from(JSON.stringify(body || {}), 'utf8');
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method: 'POST', timeout: 20000, headers: { 'content-type': 'application/json', 'content-length': payload.length, accept: 'application/json' } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch (e) {
          reject(new Error('the endpoint did not return json, ' + e.message));
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('the request timed out')));
    req.end(payload);
  });
}

async function verifyEndpoint(net, base) {
  const info = await post(base, 'node_info', {});
  if (info.chain_id !== net.chainId) throw new Error('chain id ' + info.chain_id + ' is not the pinned ' + net.chainId);
  if (info.genesis_hash !== net.genesis) throw new Error('genesis ' + info.genesis_hash + ' is not the pinned ' + net.genesis);
  const cp = net.finality && net.finality.checkpoint;
  if (cp) {
    const fin = await post(base, 'get_finality', { height: cp.height });
    if (fin.header_hash !== cp.hash) throw new Error('the block at height ' + cp.height + ' hashes to ' + fin.header_hash + ' not the pinned ' + cp.hash);
  }
  return cp ? cp.height : null;
}

async function main() {
  const only = process.argv[2];
  const names = only ? [only] : Object.keys(NETWORKS);
  let failed = 0;
  for (const name of names) {
    const net = NETWORKS[name];
    const bases = officialEndpointsOf(net).map((e) => e.url);
    if (bases.length === 0) {
      console.log(name + ' has no official endpoint to verify against');
      continue;
    }
    for (const base of bases) {
      try {
        const h = await verifyEndpoint(net, base);
        console.log('ok   ' + name + ' at ' + base + ' matches the pinned chain id, genesis' + (h !== null ? ' and checkpoint at height ' + h : ''));
      } catch (e) {
        failed += 1;
        console.log('FAIL ' + name + ' at ' + base + ', ' + e.message);
      }
    }
  }
  if (failed) {
    console.error(failed + ' endpoint check' + (failed === 1 ? '' : 's') + ' did not match the pinned trust anchor');
    process.exit(1);
  }
  console.log('the pinned chain id, genesis and checkpoint match every official endpoint');
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
