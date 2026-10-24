// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { core } = require('@quantovainc/qcore');
const wire = require('../lib/wire');
const { eventLeaf } = require('../lib/finality');
const { decode } = require('../lib/bech32m');
const { NETWORKS, deepFreeze } = require('../lib/networks');

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
    for (let i = 0; i < 5; i += 1) if ((top >>> i) & 1) chk = (chk ^ GEN[i]) >>> 0;
  }
  return chk;
}

function encode(hrp, bytes) {
  const h = hrp.toLowerCase();
  const data = [];
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      data.push((acc >> bits) & 31);
    }
  }
  if (bits) data.push((acc << (5 - bits)) & 31);
  const expand = [];
  for (const c of h) expand.push(c.charCodeAt(0) >> 5);
  expand.push(0);
  for (const c of h) expand.push(c.charCodeAt(0) & 31);
  const mod = polymod(expand.concat(data, [0, 0, 0, 0, 0, 0])) ^ 0x2bc830a3;
  const checksum = [];
  for (let p = 0; p < 6; p += 1) checksum.push((mod >>> (5 * (5 - p))) & 31);
  return (h + '1' + data.concat(checksum).map((d) => CHARSET[d]).join('')).toUpperCase();
}

const sha3 = (...parts) => {
  const h = crypto.createHash('sha3-256');
  for (const p of parts) h.update(p);
  return h.digest();
};

function split(n) {
  let s = 1;
  while (s << 1 < n) s <<= 1;
  return s;
}

function merkleRoot(leaves) {
  if (leaves.length === 0) return sha3(Buffer.alloc(0));
  if (leaves.length === 1) return leaves[0];
  const s = split(leaves.length);
  return sha3(Buffer.from([1]), merkleRoot(leaves.slice(0, s)), merkleRoot(leaves.slice(s)));
}

function merkleSteps(leaves, index) {
  if (leaves.length <= 1) return [];
  const s = split(leaves.length);
  if (index < s) return merkleSteps(leaves.slice(0, s), index).concat([{ sibling: merkleRoot(leaves.slice(s)).toString('hex'), left: false }]);
  return merkleSteps(leaves.slice(s), index - s).concat([{ sibling: merkleRoot(leaves.slice(0, s)).toString('hex'), left: true }]);
}

function u64le(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
}

function lengthPrefixed(bytes) {
  return Buffer.concat([u64le(bytes.length), bytes]);
}

function addressPayload(address) {
  try {
    return decode(address, 'Q', 32);
  } catch (e) {
    return Buffer.from(String(address), 'utf8');
  }
}

function wrapperBytes(o) {
  const fee = Buffer.alloc(16);
  fee.writeBigUInt64LE(BigInt(o.fee === undefined ? 2000 : o.fee));
  return Buffer.concat([
    lengthPrefixed(addressPayload(o.from)), u64le(o.nonce || 0), u64le(200000), fee,
    lengthPrefixed(addressPayload(o.to)), lengthPrefixed(o.args), u64le(0), u64le(o.chainId), lengthPrefixed(Buffer.alloc(0)),
    u64le(o.validUntil || 0), Buffer.from([o.kind === undefined ? 1 : o.kind, 1]), lengthPrefixed(sha3(Buffer.from('signature'), o.args, u64le(o.nonce || 0))),
  ]);
}

function headerBytes(height, time, eventRoot, transactionRoot) {
  const proposer = Buffer.from('validator-1');
  return Buffer.concat([
    u64le(height), Buffer.alloc(32, 1), Buffer.alloc(32, 2), transactionRoot || Buffer.alloc(32, 3), eventRoot, Buffer.alloc(32, 4),
    u64le(proposer.length), proposer, u64le(time), u64le(0),
  ]);
}

function checkpointHeader(genesis) {
  return headerBytes(0, NETWORKS.testnet.genesisTime, Buffer.from(genesis, 'hex'), Buffer.alloc(32));
}

function checkpointOf(genesis) {
  return { height: 0, hash: sha3(checkpointHeader(genesis)).toString('hex') };
}

const CHECKPOINT = checkpointOf(NETWORKS.testnet.genesis);

function checkpointReply(epoch, chainId, genesis) {
  const bytes = checkpointHeader(genesis || NETWORKS.testnet.genesis);
  return { height: 0, epoch, chain_id: chainId, header_bytes: bytes.toString('hex'), header_hash: sha3(bytes).toString('hex'), certificate: '00' };
}

function testNetwork(overrides) {
  const base = JSON.parse(JSON.stringify(NETWORKS.testnet));
  base.finality = { genesis: base.genesis, checkpoint: null, epochBlocks: null, rosters: {} };
  const o = Object.assign({}, overrides || {});
  if (o.finality && o.finality.rosters && !('checkpoint' in o.finality)) o.finality = Object.assign({ checkpoint: checkpointOf(o.genesis || base.genesis) }, o.finality);
  return deepFreeze(Object.assign(base, o));
}

function makeChain(opts) {
  const o = opts || {};
  const net = o.net || NETWORKS.testnet;
  const now = Math.floor(Date.now() / 1000);
  const chain = {
    net,
    chainId: net.chainId,
    genesis: net.genesis,
    contract: net.contract,
    time: o.time || now - 600,
    height: o.height || Math.floor(((o.time || now - 600) - net.genesisTime) * 4),
    numericChainId: BigInt(core.chainIdFromName(net.chainId)),
    txs: new Map(),
    txLeaves: new Map(),
    txAt: new Map(),
    submitted: 0,
    events: new Map(),
    blocks: new Map(),
    storage: new Map(),
    nonces: new Map(),
    epoch: o.epoch === undefined ? 0 : o.epoch,
    certify: null,
  };
  function newBlock(t) {
    chain.height += 1;
    chain.time = t === undefined ? chain.time + 1 : t;
    const h = chain.height;
    const entry = { height: h, time: chain.time };
    Object.defineProperty(entry, 'block', {
      enumerable: true,
      get: () => encode('QBK', sha3(chain.headerAt(h, entry.time))),
    });
    chain.blocks.set(h, entry);
    chain.events.set(chain.height, []);
    chain.txLeaves.set(chain.height, []);
    return chain.blocks.get(chain.height);
  }
  newBlock(chain.time);
  chain.newBlock = newBlock;
  chain.submitCall = (from, to, argsHex) => {
    const raw = Buffer.from(argsHex, 'hex');
    const sel = raw.subarray(0, 4).toString('hex');
    const blk = newBlock();
    chain.submitted += 1;
    const leaf = wrapperBytes({ from, to, args: raw, nonce: chain.submitted, chainId: chain.numericChainId, validUntil: blk.height + 64 });
    const txId = encode('QTX', sha3(leaf));
    chain.txAt.set(txId, { height: blk.height, index: chain.txLeaves.get(blk.height).length });
    chain.txLeaves.get(blk.height).push(leaf);
    let ok = true;
    let eventSel;
    let data;
    const read = (where, role, width) => raw.subarray(4 + where.at[role], 4 + where.at[role] + width);
    if (sel === wire.STAMP_UNTIL_SELECTOR) {
      const where = wire.LAYOUTS.stampUntil;
      const until = Number(read(where, 'until', 8).readBigUInt64BE(0));
      const anchored = Buffer.concat([read(where, 'hi', 16), read(where, 'lo', 16)]);
      const kind = read(where, 'kind', 8).readBigUInt64BE(0).toString();
      if (blk.time > until) ok = false;
      eventSel = wire.STAMPED_UNTIL_SELECTOR;
      data = wire.stampedEventData(from, anchored, kind, until);
    } else {
      const where = wire.LAYOUTS.stamp;
      const anchored = Buffer.concat([read(where, 'hi', 16), read(where, 'lo', 16)]);
      const kind = read(where, 'kind', 8).readBigUInt64BE(0).toString();
      eventSel = to === chain.contract ? wire.STAMPED_SELECTOR : chain.customSelector || wire.STAMPED_SELECTOR;
      data = wire.stampedEventData(from, anchored, kind);
    }
    const record = { status: 'finalised', height: blk.height, from, to, kind: 'call', raw: raw.toString('hex') };
    Object.defineProperty(record, 'block', { enumerable: true, get: () => blk.block });
    chain.txs.set(txId, record);
    if (ok) chain.events.get(blk.height).push({ contract: to, selector: eventSel, data });
    newBlock();
    return txId;
  };
  chain.leavesAt = (h) => (chain.events.get(h) || []).map((e) => eventLeaf(e.contract, e.selector, e.data));
  chain.transactionRootAt = (h) => merkleRoot((chain.txLeaves.get(h) || []).map((l) => sha3(Buffer.from([0]), l)));
  chain.headerAt = (h, time) => headerBytes(h, time, merkleRoot(chain.leavesAt(h).map((l) => sha3(Buffer.from([0]), l))), chain.transactionRootAt(h));
  chain.transactionProofAt = (id) => {
    const at = chain.txAt.get(id);
    if (!at) return null;
    const leaves = chain.txLeaves.get(at.height).map((l) => sha3(Buffer.from([0]), l));
    return {
      tx_id: id,
      height: at.height,
      index: at.index,
      transaction_root: merkleRoot(leaves).toString('hex'),
      leaf: chain.txLeaves.get(at.height)[at.index].toString('hex'),
      steps: merkleSteps(leaves, at.index),
    };
  };
  chain.finalityAt = (h) => {
    if (h === 0) return checkpointReply(chain.epoch, chain.chainId, chain.genesis);
    const b = chain.blocks.get(h);
    if (!b) return null;
    const bytes = chain.headerAt(h, b.time);
    const hash = sha3(bytes).toString('hex');
    return {
      height: h,
      epoch: chain.epoch,
      chain_id: chain.chainId,
      header_bytes: bytes.toString('hex'),
      header_hash: hash,
      certificate: chain.certify ? chain.certify(h, hash) : '00',
    };
  };
  chain.eventProofAt = (h, index) => {
    const raw = chain.leavesAt(h);
    if (index < 0 || index >= raw.length) return null;
    const leaves = raw.map((l) => sha3(Buffer.from([0]), l));
    return {
      height: h,
      index,
      event_count: raw.length,
      event_root: merkleRoot(leaves).toString('hex'),
      leaf: raw[index].toString('hex'),
      steps: merkleSteps(leaves, index),
    };
  };
  chain.validatorSetAt = (epoch) => {
    if (epoch !== chain.epoch || !chain.roster) return null;
    const total = chain.roster.reduce((sum, m) => sum + BigInt(m.stake), 0n);
    return {
      epoch,
      chain_id: chain.chainId,
      total_stake: total.toString(),
      members: chain.roster.map((m) => ({ id: m.id, stake: m.stake, bond_address: m.bond_address, attest_pk: m.attest_pk, root: m.root, root_slots: m.root_slots })),
    };
  };
  chain.revoke = (contract, tag, keyHex, reason) => {
    chain.storage.set(contract + '/' + core.mapSlotKey(tag, keyHex), String(reason));
  };
  return chain;
}

function api(chain, ov) {
  const o = ov || {};
  return {
    nodeInfo: async () => (o.nodeInfo ? o.nodeInfo(chain) : { chain_id: chain.chainId, genesis_hash: chain.genesis, head_height: chain.height, protocol: core.gatewayProtocol() }),
    block: async (h) => {
      if (o.block) return o.block(chain, h);
      const b = chain.blocks.get(Number(h));
      return b ? Object.assign({}, b) : null;
    },
    events: async (h) => {
      if (o.events) return o.events(chain, h);
      return { events: (chain.events.get(Number(h)) || []).map((e) => Object.assign({}, e)) };
    },
    transaction: async (id) => {
      if (o.transaction) return o.transaction(chain, id);
      const t = chain.txs.get(id);
      return t ? Object.assign({}, t) : { status: 'unknown' };
    },
    storageAt: async (contract, keys) => ({
      slots: keys.map((k) => ({ slot: k, value: chain.storage.has(contract + '/' + k) ? chain.storage.get(contract + '/' + k) : '0' })),
    }),
    finality: async (h) => (o.finality ? o.finality(chain, h) : chain.finalityAt(Number(h))),
    eventProof: async (h, i) => (o.eventProof ? o.eventProof(chain, h, i) : chain.eventProofAt(Number(h), Number(i))),
    transactionProof: async (id) => {
      const proof = o.transactionProof ? o.transactionProof(chain, id) : chain.transactionProofAt(id);
      if (proof === null) throw new Error('no finalized transaction ' + id);
      return proof;
    },
    validatorSet: async (e) => (o.validatorSet ? o.validatorSet(chain, e) : chain.validatorSetAt(Number(e))),
    rosterProof: async (e) => o.rosterProof(chain, Number(e)),
  };
}

function client(chain, base, overrides) {
  const o = overrides || {};
  const c = Object.assign({ base }, api(chain, o));
  if (o.operator) c.operator = o.operator;
  if (o.noState) delete c.storageAt;
  if (!o.rosterProof) delete c.rosterProof;
  if (!o.proofs) {
    delete c.finality;
    delete c.eventProof;
    delete c.validatorSet;
  }
  if (!o.proofs || o.noTransactionProofs) delete c.transactionProof;
  c.call = async (seed, index, to, argsHex) => {
    if (o.call) return o.call(chain, seed, index, to, argsHex);
    const from = core.address(seed, index);
    const nonce = chain.nonces.get(from) || 0;
    await new Promise((resolve) => setTimeout(resolve, 10));
    if ((chain.nonces.get(from) || 0) !== nonce) return { outcome: { verdict: 'rejected', reason: 'nonce ' + nonce + ' was already used' } };
    chain.nonces.set(from, nonce + 1);
    const txId = chain.submitCall(from, to, argsHex);
    chain.txs.get(txId).nonce = nonce;
    return { outcome: { verdict: 'accepted', tx_id: txId } };
  };
  return c;
}

function gateway(chain, overrides) {
  const handlers = api(chain, overrides);
  const o = overrides || {};
  const handler = (req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const method = req.url.replace(/^\/v1\//, '');
      let body = {};
      try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
      } catch (e) {
        body = {};
      }
      const send = (status, value) => {
        const text = typeof value === 'string' ? value : JSON.stringify(value);
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(text);
      };
      try {
        if (o.status) return send(o.status, o.reply || { message: 'unavailable' });
        if (method === 'node_info') return send(200, await handlers.nodeInfo());
        if (method === 'get_transaction') return send(200, await handlers.transaction(body.tx_id));
        if (method === 'get_events') return send(200, await handlers.events(body.height));
        if (method === 'get_block') return send(200, await handlers.block(body.height));
        if (method === 'get_storage_at') return send(200, await handlers.storageAt(body.address, body.keys));
        if (method === 'get_finality' && o.proofs) return send(200, await handlers.finality(body.height));
        if (method === 'get_event_proof' && o.proofs) return send(200, await handlers.eventProof(body.height, body.index));
        if (method === 'get_transaction_proof' && o.proofs && !o.noTransactionProofs) {
          try {
            return send(200, await handlers.transactionProof(body.tx_id));
          } catch (e) {
            return send(404, { message: 'no finalized transaction' });
          }
        }
        if (method === 'get_validator_set' && o.proofs) {
          const set = await handlers.validatorSet(body.epoch);
          return set ? send(200, set) : send(404, { message: 'only the roster of the current epoch is served' });
        }
        return send(404, { message: 'unknown method' });
      } catch (e) {
        return send(500, { message: String(e.message) });
      }
    });
  };
  const server = o.tls ? https.createServer(o.tls, handler) : http.createServer(handler);
  return new Promise((resolve) => {
    const host = o.host || '127.0.0.1';
    server.listen(0, host, () => {
      const { port } = server.address();
      const shown = host.includes(':') ? '[' + host + ']' : host;
      resolve({ url: (o.tls ? 'https' : 'http') + '://' + shown + ':' + port, port, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

const SEED = new Uint8Array(32).fill(7);

module.exports = { makeChain, client, gateway, encode, SEED, testNetwork, CHECKPOINT, checkpointOf, checkpointReply, merkleRoot, merkleSteps, headerBytes, wrapperBytes, sha3 };
