// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const crypto = require('crypto');
const { core } = require('@quantovainc/qcore');
const { algorithmId, parseDigest } = require('./hash');
const { leafHash, tree, commitment, SALT_BYTES } = require('./merkle');
const { stampArgs, stampedEventData, STAMPED_SELECTOR } = require('./wire');
const { FORMAT, kindValue, validate } = require('./receipt');
const { network } = require('./networks');
const { clientFor, read, checkedTimeout, waitFinal, isTransient, clean } = require('./client');

const PENDING_FORMAT = 'qstamp-pending/1';
const DEFAULT_METER = 30000;
const DEFAULT_MAX_FEE = '50000';
const DEFAULT_TIMEOUT_MS = 60000;
const ZERO_SALT = Buffer.alloc(SALT_BYTES);

function normaliseRecords(records) {
  if (!Array.isArray(records) || records.length === 0) throw new Error('stamping needs at least one record');
  const seen = new Set();
  return records.map((r, i) => {
    if (!r || typeof r !== 'object') throw new Error('record ' + i + ' must be an object');
    const alg = r.alg === undefined ? 'sha3-256' : r.alg;
    algorithmId(alg);
    let digest;
    try {
      digest = parseDigest(r.digest);
    } catch (e) {
      throw new Error('record ' + i + ' needs a 32 byte digest');
    }
    let salt;
    try {
      salt = r.salt === undefined ? crypto.randomBytes(SALT_BYTES) : parseDigest(r.salt);
    } catch (e) {
      throw new Error('record ' + i + ' needs a 32 byte salt');
    }
    if (salt.equals(ZERO_SALT)) throw new Error('record ' + i + ' needs a random salt, not zeros');
    const key = salt.toString('hex');
    if (seen.has(key)) throw new Error('record ' + i + ' reuses a salt from the same batch');
    seen.add(key);
    return { alg, digest, salt };
  });
}

function prepare(records) {
  const recs = normaliseRecords(records);
  const leaves = recs.map((r) => leafHash(r.alg, r.digest, r.salt));
  const { root, paths } = tree(leaves);
  return { recs, root, paths };
}

function seedCopy(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new Error('the signing seed must be a Uint8Array of 32 bytes, which the caller can wipe after use');
  }
  return Uint8Array.from(seed);
}

async function checkChain(client, net) {
  const info = await read(() => client.nodeInfo());
  if (!info || info.chain_id !== net.chainId || info.genesis_hash !== net.genesis) {
    throw new Error('the rpc endpoint does not serve the ' + net.name + ' chain');
  }
}

function pendingOf(net, kind, sender, prepared, anchored, txId) {
  return {
    format: PENDING_FORMAT,
    network: net.name,
    contract: net.contract,
    kind,
    sender,
    tx: txId,
    commitment: anchored.toString('hex'),
    records: prepared.recs.map((r) => ({ alg: r.alg, digest: r.digest.toString('hex'), salt: r.salt.toString('hex') })),
  };
}

async function anchorOf(client, pending, anchored, timeoutMs) {
  const tx = await waitFinal(client, pending.tx, timeoutMs);
  if (!tx) {
    const err = new Error('the stamp transaction ' + pending.tx + ' is not final yet, finish it later with complete');
    err.code = 'QSTAMP_PENDING';
    throw err;
  }
  if (tx.from !== pending.sender || tx.to !== pending.contract || tx.kind !== 'call') {
    throw new Error('the finalised transaction does not match the stamp that was sent');
  }
  const events = await read(() => client.events(tx.height));
  const want = stampedEventData(pending.sender, anchored, pending.kind);
  const list = events && Array.isArray(events.events) ? events.events : [];
  const found = list.some(
    (e) => e && typeof e === 'object' && e.contract === pending.contract && e.selector === STAMPED_SELECTOR &&
      typeof e.data === 'string' && e.data.toLowerCase() === want,
  );
  if (!found) {
    const err = new Error(events && events.truncated
      ? 'the block event list was truncated by the endpoint, finish the stamp later with complete'
      : 'the stamp transaction finalised but the contract did not record the stamp');
    err.code = events && events.truncated ? 'QSTAMP_PENDING' : 'QSTAMP_NOT_RECORDED';
    throw err;
  }
  const block = await read(() => client.block(tx.height));
  if (!block || block.block !== tx.block || !Number.isSafeInteger(block.time)) {
    throw new Error('the block holding the stamp could not be confirmed');
  }
  return { tx: pending.tx, height: tx.height, block: tx.block, time: block.time, sender: pending.sender };
}

function receiptsFor(net, pending, prepared, anchor) {
  return prepared.recs.map((r, i) =>
    validate({
      format: FORMAT,
      chain: { id: net.chainId, genesis: net.genesis },
      contract: pending.contract,
      kind: pending.kind,
      record: { alg: r.alg, digest: r.digest.toString('hex'), salt: r.salt.toString('hex') },
      proof: { index: i, size: prepared.recs.length, path: prepared.paths[i].map((p) => p.toString('hex')) },
      root: prepared.root.toString('hex'),
      anchor,
    }),
  );
}

async function finish(client, net, pending, prepared, anchored, timeoutMs) {
  try {
    const anchor = await anchorOf(client, pending, anchored, timeoutMs);
    return receiptsFor(net, pending, prepared, anchor);
  } catch (e) {
    e.pending = pending;
    throw e;
  }
}

async function stamp(options) {
  const opts = options || {};
  const net = network(opts.network === undefined ? 'testnet' : opts.network);
  if (opts.contract !== undefined && opts.contract !== net.contract) {
    throw new Error('stamping goes only through the official contract of the ' + net.name + ' network');
  }
  if (!Number.isSafeInteger(opts.index) || opts.index < 0) throw new Error('a signing account index is required');
  const kind = kindValue(opts.kind === undefined ? 'record' : opts.kind);
  const timeoutMs = checkedTimeout(opts.timeoutMs, DEFAULT_TIMEOUT_MS);
  const meter = opts.meter === undefined ? DEFAULT_METER : opts.meter;
  if (!Number.isSafeInteger(meter) || meter < 10000 || meter > 1000000) throw new Error('the meter must be between 10000 and 1000000');
  const maxFee = opts.maxFee === undefined ? DEFAULT_MAX_FEE : String(opts.maxFee);
  if (!/^[1-9][0-9]{0,18}$/.test(maxFee)) throw new Error('the maximum fee must be a whole number of quon');
  const prepared = prepare(opts.records);
  const client = clientFor(opts.client || opts.rpc || net.rpc, net.chainId);
  await checkChain(client, net);
  const seed = seedCopy(opts.seed);
  let sender;
  let anchored;
  let outcome;
  try {
    sender = core.address(seed, opts.index);
    anchored = commitment(prepared.root, prepared.recs.length, { genesis: net.genesis, contract: net.contract, sender, kind });
    ({ outcome } = await client.call(seed, opts.index, net.contract, stampArgs(anchored, kind), meter, maxFee));
  } catch (e) {
    if (anchored && isTransient(e)) {
      e.pending = pendingOf(net, kind, sender, prepared, anchored, null);
      e.code = 'QSTAMP_UNCONFIRMED';
    }
    throw e;
  } finally {
    seed.fill(0);
  }
  if (!outcome || outcome.verdict !== 'accepted' || typeof outcome.tx_id !== 'string' || !/^QTX1[0-9A-Z]+$/.test(outcome.tx_id)) {
    throw new Error('the chain refused the stamp' + (outcome && outcome.reason ? ' (' + clean(outcome.reason, 200) + ')' : ''));
  }
  const pending = pendingOf(net, kind, sender, prepared, anchored, outcome.tx_id);
  if (typeof opts.onPending === 'function') {
    try {
      await opts.onPending(pending);
    } catch (e) {
      e.pending = pending;
      throw e;
    }
  }
  return finish(client, net, pending, prepared, anchored, timeoutMs);
}

async function complete(pending, options) {
  const opts = options || {};
  if (!pending || typeof pending !== 'object' || pending.format !== PENDING_FORMAT) {
    throw new Error('complete needs a pending stamp in the ' + PENDING_FORMAT + ' format');
  }
  const net = network(pending.network);
  if (pending.contract !== net.contract) throw new Error('the pending stamp names an unofficial contract');
  if (typeof pending.tx !== 'string' || !/^QTX1[0-9A-Z]{20,120}$/.test(pending.tx)) {
    throw new Error('the pending stamp has no transaction id, look up the transaction sent from ' + String(pending.sender).slice(0, 80) + ' and supply its id');
  }
  if (typeof pending.sender !== 'string' || !core.valid_address(pending.sender)) throw new Error('the pending stamp names an invalid signer');
  if (typeof pending.commitment !== 'string' || !/^[0-9a-f]{64}$/.test(pending.commitment)) throw new Error('the pending stamp has no valid commitment');
  const kind = kindValue(pending.kind);
  const prepared = prepare(pending.records);
  const anchored = commitment(prepared.root, prepared.recs.length, {
    genesis: net.genesis, contract: pending.contract, sender: pending.sender, kind,
  });
  if (anchored.toString('hex') !== pending.commitment) throw new Error('the pending records do not match the anchored commitment');
  const client = clientFor(opts.client || opts.rpc || net.rpc, net.chainId);
  await checkChain(client, net);
  return finish(client, net, Object.assign({}, pending, { kind }), prepared, anchored,
    checkedTimeout(opts.timeoutMs, DEFAULT_TIMEOUT_MS));
}

module.exports = { stamp, complete, prepare, PENDING_FORMAT };
