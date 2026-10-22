// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const crypto = require('crypto');
const { core } = require('@quantovainc/qcore');
const { algorithmId, parseDigest } = require('./hash');
const { leafHash, tree, commitment, SALT_BYTES, MAX_LEAVES } = require('./merkle');
const { stampArgs, stampedEventData, stampedSelector, untilWord, callMatches } = require('./wire');
const { FORMAT, kindValue, validate } = require('./receipt');
const { network } = require('./networks');
const { read, checkedTimeout, waitFinal, isTransient, clean, failureCode } = require('./client');
const { endpointsFor, chainTimeWith, clientOf } = require('./endpoints');
const D = require('./deadline');

const PENDING_FORMAT = 'qstamp-pending/1';
const DEFAULT_METER = 30000;
const DEFAULT_MAX_FEE = '1000';
const DEFAULT_TIMEOUT_MS = 60000;
const DEFAULT_DEADLINE_EXTRA_MS = 120000;
const senderLocks = new Map();
const ZERO_SALT = Buffer.alloc(SALT_BYTES);
const PURPOSE_BASE = 1 << 20;
const PURPOSE_SPAN = 2 ** 31 - PURPOSE_BASE;
const PURPOSE_MAX = 128;

function purposeIndex(purpose) {
  if (typeof purpose !== 'string' || purpose.length === 0 || purpose.length > PURPOSE_MAX || /[\u0000-\u001f\u007f-\u009f]/.test(purpose) || purpose !== purpose.normalize('NFC')) {
    throw new Error('a purpose is a label of 1 to ' + PURPOSE_MAX + ' characters in NFC form without control characters');
  }
  const h = crypto.createHash('sha3-256').update('QSTAMP/PURPOSE/V1').update(Buffer.from([0])).update(Buffer.from(purpose, 'utf8')).digest();
  return PURPOSE_BASE + (h.readUInt32BE(0) % PURPOSE_SPAN);
}

function normaliseRecords(records) {
  if (!Array.isArray(records) || records.length === 0) throw new Error('stamping needs at least one record');
  if (records.length > MAX_LEAVES) throw new Error('a batch holds at most ' + MAX_LEAVES + ' records');
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
  if (!((ArrayBuffer.isView(seed) && seed instanceof Uint8Array)) || seed.length !== 32) {
    throw new Error('the signing seed must be a Uint8Array of 32 bytes, which the caller can wipe after use');
  }
  return Uint8Array.from(seed);
}

function outside(e, what) {
  const code = e && e.code === 'QSTAMP_TRANSPORT' ? failureCode(e) : 'error';
  const err = new Error(clean(what + ' (' + code + ')', 200), { cause: e });
  if (e && e.code === 'QSTAMP_TRANSPORT') {
    err.code = 'QSTAMP_TRANSPORT';
    err.reason = code;
  }
  err.transient = isTransient(e);
  return err;
}

async function guarded(what, fn) {
  try {
    return await fn();
  } catch (e) {
    throw outside(e, what);
  }
}

function lockSender(key) {
  const prior = senderLocks.get(key) || Promise.resolve();
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const tail = prior.then(() => gate);
  senderLocks.set(key, tail);
  tail.then(() => {
    if (senderLocks.get(key) === tail) senderLocks.delete(key);
  });
  return D.within(prior).then(() => release, (e) => {
    release();
    throw outside(e, 'another stamp from the same account was still in progress, nothing was sent');
  });
}

async function checkChain(client, net) {
  const info = await guarded('the rpc endpoint could not answer', () => read(() => client.nodeInfo()));
  if (!info || info.chain_id !== net.chainId || info.genesis_hash !== net.genesis) {
    throw new Error('the rpc endpoint does not serve the ' + net.name + ' chain');
  }
}

function untilIn(pending) {
  return Object.prototype.hasOwnProperty.call(pending, 'until') ? pending.until : undefined;
}

function pendingOf(net, kind, sender, prepared, anchored, txId, until) {
  const out = {
    format: PENDING_FORMAT,
    network: net.name,
    contract: net.contract,
    kind,
    sender,
    tx: txId,
    commitment: anchored.toString('hex'),
    records: prepared.recs.map((r) => ({ alg: r.alg, digest: r.digest.toString('hex'), salt: r.salt.toString('hex') })),
  };
  if (until !== undefined) out.until = until;
  return out;
}

async function anchorOf(client, pending, anchored, timeoutMs) {
  const tx = await guarded('the stamp transaction could not be read', () => waitFinal(client, pending.tx, timeoutMs));
  if (!tx) {
    const err = new Error('the stamp transaction ' + pending.tx + ' is not final yet, finish it later with complete');
    err.code = 'QSTAMP_PENDING';
    throw err;
  }
  if (tx.from !== pending.sender || tx.to !== pending.contract || tx.kind !== 'call') {
    throw new Error('the finalised transaction does not match the stamp that was sent');
  }
  const raw = typeof tx.raw === 'string' && /^[0-9a-fA-F]*$/.test(tx.raw) && tx.raw.length % 2 === 0 ? Buffer.from(tx.raw, 'hex') : null;
  if (!callMatches(raw, anchored, pending.kind, untilIn(pending))) {
    throw new Error('the finalised transaction ' + pending.tx + ' does not carry the commitment of this stamp');
  }
  const events = await guarded('the events of the block holding the stamp could not be read', () => read(() => client.events(tx.height)));
  const want = stampedEventData(pending.sender, anchored, pending.kind, untilIn(pending));
  const selector = stampedSelector(untilIn(pending));
  const list = events && Array.isArray(events.events) ? events.events : [];
  const found = list.some(
    (e) => e && typeof e === 'object' && e.contract === pending.contract && e.selector === selector &&
      typeof e.data === 'string' && e.data.toLowerCase() === want,
  );
  if (!found) {
    const err = new Error(events && events.truncated
      ? 'the block event list was truncated by the endpoint, finish the stamp later with complete'
      : 'the stamp transaction finalised but the contract did not record the stamp');
    err.code = events && events.truncated ? 'QSTAMP_PENDING' : 'QSTAMP_NOT_RECORDED';
    throw err;
  }
  const block = await guarded('the block holding the stamp could not be read', () => read(() => client.block(tx.height)));
  if (!block || block.block !== tx.block || block.height !== tx.height || !Number.isSafeInteger(block.time)) {
    throw new Error('the block holding the stamp could not be confirmed');
  }
  if (untilIn(pending) !== undefined && block.time > untilIn(pending)) throw new Error('the block holding the stamp is later than its deadline');
  return { tx: pending.tx, height: tx.height, block: tx.block, time: block.time, sender: pending.sender };
}

function receiptsFor(net, pending, prepared, anchor) {
  return prepared.recs.map((r, i) =>
    validate(Object.assign({
      format: FORMAT,
      chain: { id: net.chainId, genesis: net.genesis },
      contract: pending.contract,
      kind: pending.kind,
      record: { alg: r.alg, digest: r.digest.toString('hex'), salt: r.salt.toString('hex') },
      proof: { index: i, size: prepared.recs.length, path: prepared.paths[i].map((p) => p.toString('hex')) },
      root: prepared.root.toString('hex'),
      anchor,
    }, untilIn(pending) === undefined ? {} : { until: untilIn(pending) })),
  );
}

async function finish(clients, net, pending, prepared, anchored, timeoutMs) {
  try {
    const anchors = [];
    for (const client of clients) anchors.push(await anchorOf(client, pending, anchored, timeoutMs));
    const first = JSON.stringify(anchors[0]);
    if (anchors.some((a) => JSON.stringify(a) !== first)) {
      const err = new Error('the endpoints report different blocks or times for the stamp transaction, so the anchor was not accepted');
      err.code = 'QSTAMP_DISAGREEMENT';
      throw err;
    }
    return receiptsFor(net, pending, prepared, anchors[0]);
  } catch (e) {
    e.pending = pending;
    throw e;
  }
}

async function clientsFor(opts, net) {
  const plan = await endpointsFor(opts, net, 'stamp');
  if (plan.refused) throw new Error(plan.refused);
  if (plan.entries.length === 0) throw new Error('no rpc endpoint is known for this chain');
  if (plan.groups.length < 2 && opts.trustSingleEndpoint !== true) {
    throw new Error('the endpoints given are not run independently of each other, so a dishonest operator could invent the chain data alone, list at least two endpoints run by different operators or set trustSingleEndpoint to true to rely on one');
  }
  return Promise.all(plan.entries.map((e) => clientOf(e, net.chainId, net.genesis)));
}

function controlFor(opts, timeoutMs) {
  const ctl = D.controlOf(opts, timeoutMs + DEFAULT_DEADLINE_EXTRA_MS);
  const stop = D.stopped(ctl);
  if (stop) throw outside(stop, 'nothing was sent');
  return ctl;
}

function reasonCode(reason) {
  const code = String(reason).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 40);
  return code.length ? code : 'unspecified';
}

function untilOf(value) {
  if (value === undefined) return undefined;
  untilWord(value);
  return value;
}

const ENDPOINT_OPTIONS = ['network', 'rpc', 'client', 'clients', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'clockSlackMs', 'deadlineMs', 'signal'];
const STAMP_OPTIONS = new Set(ENDPOINT_OPTIONS.concat(['seed', 'index', 'records', 'kind', 'until', 'contract', 'meter', 'maxFee', 'timeoutMs', 'onPending']));
const COMPLETE_OPTIONS = new Set(ENDPOINT_OPTIONS.concat(['seed', 'index', 'timeoutMs', 'onPending']));

function onlyKnown(options, allowed, name) {
  if (options === undefined || options === null) return;
  if (typeof options !== 'object' || Array.isArray(options) || ArrayBuffer.isView(options)) throw new Error('the options of ' + name + ' are a plain object');
  const unknown = Object.keys(options).find((k) => !allowed.has(k));
  if (unknown !== undefined) throw new Error('the option ' + unknown.replace(/[^A-Za-z0-9_]/g, '?').slice(0, 40) + ' is not an option of ' + name + ', so nothing was signed');
}

async function stamp(options) {
  onlyKnown(options, STAMP_OPTIONS, 'stamp');
  const opts = Object.assign(Object.create(null), options);
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
  const until = untilOf(opts.until);
  const prepared = prepare(opts.records);
  const ctl = controlFor(opts, timeoutMs);
  return D.runWith(ctl, () => stampIn(opts, { net, kind, timeoutMs, meter, maxFee, until, prepared }));
}

async function stampIn(opts, p) {
  const { net, kind, timeoutMs, meter, maxFee, until, prepared } = p;
  const clients = await clientsFor(opts, net);
  const client = clients[0];
  for (const c of clients) await checkChain(c, net);
  if (until !== undefined) {
    const clock = await chainTimeWith(Object.assign({}, opts, { network: net.name }), { allowCustom: true });
    if (Math.floor(clock.late / 1000) > until) throw new Error('the stamp deadline has already passed on the chain, nothing was sent');
  }
  const seed = seedCopy(opts.seed);
  let sender;
  let anchored;
  try {
    sender = core.address(seed, opts.index);
    anchored = commitment(prepared.root, prepared.recs.length, { genesis: net.genesis, contract: net.contract, sender, kind });
  } catch (e) {
    seed.fill(0);
    throw outside(e, 'the signing account could not be derived');
  }
  let unlock;
  try {
    unlock = await lockSender(net.genesis + '/' + sender);
  } catch (e) {
    seed.fill(0);
    throw e;
  }
  try {
    let outcome;
    try {
      ({ outcome } = await D.within(client.call(seed, opts.index, net.contract, stampArgs(anchored, kind, until), meter, maxFee)));
    } catch (e) {
      const err = outside(e, 'the stamp could not be submitted');
      if (isTransient(e) || D.isStop(e)) {
        err.pending = pendingOf(net, kind, sender, prepared, anchored, null, until);
        err.code = 'QSTAMP_UNCONFIRMED';
      }
      throw err;
    } finally {
      seed.fill(0);
    }
    if (!outcome || outcome.verdict !== 'accepted' || typeof outcome.tx_id !== 'string' || !/^QTX1[0-9A-Z]+$/.test(outcome.tx_id)) {
      throw new Error('the chain refused the stamp' + (outcome && outcome.reason ? ' (' + reasonCode(outcome.reason) + ')' : ''));
    }
    const pending = pendingOf(net, kind, sender, prepared, anchored, outcome.tx_id, until);
    if (typeof opts.onPending === 'function') {
      try {
        await D.within(D.outside(() => opts.onPending(pending)));
      } catch (e) {
        const err = D.isStop(e) ? outside(e, 'onPending did not finish before the deadline passed or the signal aborted, finish the stamp later with complete') : e;
        if (err && typeof err === 'object') err.pending = pending;
        throw err;
      }
    }
    return await finish(clients, net, pending, prepared, anchored, timeoutMs);
  } finally {
    unlock();
  }
}

async function complete(pending, options) {
  onlyKnown(options, COMPLETE_OPTIONS, 'complete');
  const opts = Object.assign(Object.create(null), options);
  if (!pending || typeof pending !== 'object' || pending.format !== PENDING_FORMAT) {
    throw new Error('complete needs a pending stamp in the ' + PENDING_FORMAT + ' format');
  }
  const net = network(pending.network);
  if (pending.contract !== net.contract) throw new Error('the pending stamp names an unofficial contract');
  if (typeof pending.tx !== 'string' || !/^QTX1[0-9A-Z]{20,120}$/.test(pending.tx)) {
    throw new Error('the pending stamp has no transaction id, look up the transaction sent from ' + (typeof pending.sender === 'string' ? pending.sender.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, '?').slice(0, 80) : 'of type ' + typeof pending.sender) + ' and supply its id');
  }
  if (typeof pending.sender !== 'string' || !core.valid_address(pending.sender)) throw new Error('the pending stamp names an invalid signer');
  if (typeof pending.commitment !== 'string' || !/^[0-9a-f]{64}$/.test(pending.commitment)) throw new Error('the pending stamp has no valid commitment');
  const kind = kindValue(pending.kind);
  const prepared = prepare(pending.records);
  const anchored = commitment(prepared.root, prepared.recs.length, {
    genesis: net.genesis, contract: pending.contract, sender: pending.sender, kind,
  });
  if (anchored.toString('hex') !== pending.commitment) throw new Error('the pending records do not match the anchored commitment');
  const until = untilOf(untilIn(pending));
  const timeoutMs = checkedTimeout(opts.timeoutMs, DEFAULT_TIMEOUT_MS);
  const ctl = controlFor(opts, timeoutMs);
  return D.runWith(ctl, async () => {
    const clients = await clientsFor(opts, net);
    for (const c of clients) await checkChain(c, net);
    const base = Object.assign({}, pending, { kind });
    if (until === undefined) delete base.until;
    return finish(clients, net, base, prepared, anchored, timeoutMs);
  });
}

module.exports = { stamp, complete, prepare, purposeIndex, PENDING_FORMAT };
