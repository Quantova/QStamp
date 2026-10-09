// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { digestBytes, digestFile, parseDigest } = require('./hash');
const { leafHash, rootFromPath, commitment } = require('./merkle');
const { stampArgs, stampedEventData, STAMPED_SELECTOR } = require('./wire');
const { validate } = require('./receipt');
const { NETWORKS } = require('./networks');
const { clientFor, read, isTransient, clean } = require('./client');

function networkFor(receipt) {
  for (const net of Object.values(NETWORKS)) {
    if (net.chainId === receipt.chain.id && net.genesis === receipt.chain.genesis) return net;
  }
  return null;
}

async function contentDigest(receipt, opts) {
  const given = ['file', 'bytes', 'digest'].filter((k) => opts[k] !== undefined);
  if (given.length > 1) throw new Error('give exactly one of file, bytes or digest');
  if (opts.file !== undefined) return digestFile(opts.file, receipt.record.alg);
  if (opts.bytes !== undefined) return digestBytes(opts.bytes, receipt.record.alg);
  if (opts.digest !== undefined) return parseDigest(opts.digest);
  return null;
}

async function chainChecks(client, receipt, anchored, label) {
  const checks = [];
  const add = (name, ok, detail, transport) =>
    checks.push({ name: label ? name + ' @ ' + label : name, ok, detail, transport: !!transport });
  const fetch = async (name, fn) => {
    try {
      return { value: await read(fn) };
    } catch (e) {
      add(name, false, 'the endpoint could not answer (' + clean((e && e.message) || e, 120) + ')', isTransient(e));
      return null;
    }
  };
  const info = await fetch('chain', () => client.nodeInfo());
  if (!info) return checks;
  const sameChain = !!info.value && info.value.chain_id === receipt.chain.id && info.value.genesis_hash === receipt.chain.genesis;
  add('chain', sameChain, sameChain ? 'the endpoint serves the chain named in the receipt' : 'the endpoint serves a different chain');
  if (!sameChain) return checks;
  const txr = await fetch('transaction', () => client.transaction(receipt.anchor.tx));
  if (txr) {
    const tx = txr.value;
    const problems = [];
    if (!tx || tx.status !== 'finalised') {
      problems.push('not final');
    } else {
      if (tx.height !== receipt.anchor.height) problems.push('height differs');
      if (tx.block !== receipt.anchor.block) problems.push('block differs');
      if (tx.from !== receipt.anchor.sender) problems.push('signer differs');
      if (tx.to !== receipt.contract) problems.push('target differs');
      if (tx.kind !== 'call') problems.push('not a contract call');
      const raw = typeof tx.raw === 'string' && /^[0-9a-fA-F]*$/.test(tx.raw) && tx.raw.length % 2 === 0 ? Buffer.from(tx.raw, 'hex') : null;
      const tail = Buffer.from(stampArgs(anchored, receipt.kind), 'hex').subarray(124);
      if (!raw || raw.indexOf(tail) < 0) problems.push('it does not carry this commitment');
    }
    add('transaction', problems.length === 0,
      problems.length ? 'the anchoring transaction does not match, ' + problems.join(', ') : 'the anchoring transaction is final and carries this commitment');
  }
  const evr = await fetch('event', () => client.events(receipt.anchor.height));
  if (evr) {
    const list = evr.value && Array.isArray(evr.value.events) ? evr.value.events : [];
    const want = stampedEventData(receipt.anchor.sender, anchored, receipt.kind);
    const found = list.some(
      (e) => e && typeof e === 'object' && e.contract === receipt.contract && e.selector === STAMPED_SELECTOR &&
        typeof e.data === 'string' && e.data.toLowerCase() === want,
    );
    if (found) add('event', true, 'the stamp contract recorded this commitment, signer and kind in that block');
    else if (evr.value && evr.value.truncated) add('event', false, 'the endpoint truncated the event list, so the result is inconclusive', true);
    else add('event', false, 'no matching stamp event was recorded in that block');
  }
  const blr = await fetch('block', () => client.block(receipt.anchor.height));
  if (blr) {
    const b = blr.value;
    const ok = !!b && b.block === receipt.anchor.block && b.height === receipt.anchor.height && b.time === receipt.anchor.time;
    add('block', ok, ok ? 'the block id and time match the receipt' : 'the block id or time differs from the receipt');
  }
  return checks;
}

function pinContract(net, opts, receipt, add) {
  const custom = opts.trustCustomContract === true;
  if (net) {
    if (opts.contract !== undefined && opts.contract !== net.contract && !custom) {
      add('contract', false, 'a contract other than the official one was requested without trustCustomContract');
      return;
    }
    const pinned = custom && opts.contract !== undefined ? opts.contract : net.contract;
    const official = pinned === net.contract;
    add('contract', pinned === receipt.contract, pinned !== receipt.contract
      ? 'the receipt names an unrecognised contract'
      : official ? 'the receipt names the official stamp contract' : 'the receipt names the contract the caller chose to trust');
    return;
  }
  if (custom && typeof opts.contract === 'string') {
    add('contract', opts.contract === receipt.contract, opts.contract === receipt.contract
      ? 'the receipt names the contract the caller chose to trust' : 'the receipt names an unrecognised contract');
    return;
  }
  add('contract', false, 'the receipt names a chain this release does not know, pass contract with trustCustomContract to accept it');
}

async function verify(input, options) {
  const opts = options || {};
  const checks = [];
  const add = (name, ok, detail, transport) => checks.push({ name, ok, detail, transport: !!transport });
  let receipt;
  try {
    receipt = JSON.parse(JSON.stringify(input));
    validate(receipt);
  } catch (e) {
    add('format', false, clean((e && e.message) || e, 300));
    return { valid: false, status: 'invalid', contentChecked: false, endpoints: [], officialEndpoints: false, checks };
  }
  add('format', true, 'the receipt is well formed');
  const net = networkFor(receipt);
  pinContract(net, opts, receipt, add);
  let content = null;
  let unreadable = false;
  try {
    content = await contentDigest(receipt, opts);
  } catch (e) {
    unreadable = true;
    add('content', false, 'the content could not be read, ' + clean((e && e.message) || e, 120));
  }
  if (!unreadable) {
    if (content === null) {
      add('content', false, 'no content was supplied, so the record itself was not checked');
    } else {
      const same = content.toString('hex') === receipt.record.digest;
      add('content', same, same ? 'the content matches the fingerprint in the receipt' : 'the content does not match the fingerprint in the receipt');
    }
  }
  const leaf = leafHash(receipt.record.alg, Buffer.from(receipt.record.digest, 'hex'), Buffer.from(receipt.record.salt, 'hex'));
  const root = Buffer.from(receipt.root, 'hex');
  const computed = rootFromPath(leaf, receipt.proof.index, receipt.proof.size, receipt.proof.path.map((p) => Buffer.from(p, 'hex')));
  const included = !!computed && computed.equals(root);
  add('inclusion', included, included ? 'the fingerprint is included in the batch root' : 'the inclusion path does not lead to the batch root');
  const anchored = commitment(root, receipt.proof.size, {
    genesis: receipt.chain.genesis, contract: receipt.contract, sender: receipt.anchor.sender, kind: receipt.kind,
  });
  const given = opts.clients || [opts.client || opts.rpc || (net ? net.rpc : null)];
  const seenTargets = new Set();
  const targets = Array.isArray(given) ? given.filter((t) => {
    if (typeof t !== 'string') {
      if (seenTargets.has(t)) return false;
      seenTargets.add(t);
      return true;
    }
    let key = t;
    try {
      const u = new URL(t);
      key = u.protocol + '//' + u.host.toLowerCase() + u.pathname.replace(/\/+$/, '');
    } catch (e) {
      key = t;
    }
    if (seenTargets.has(key)) return false;
    seenTargets.add(key);
    return true;
  }) : given;
  const endpoints = [];
  if (!Array.isArray(targets) || targets.length === 0 || targets.some((t) => !t)) {
    add('anchor', false, 'no rpc endpoint is known for this chain', true);
  } else {
    for (let i = 0; i < targets.length; i += 1) {
      let client;
      try {
        client = clientFor(targets[i], receipt.chain.id);
      } catch (e) {
        add('anchor', false, clean((e && e.message) || e, 200));
        continue;
      }
      endpoints.push(typeof targets[i] === 'string' ? targets[i] : 'custom client');
      const label = targets.length > 1 ? String(i + 1) : '';
      for (const c of await chainChecks(client, receipt, anchored, label)) checks.push(c);
    }
  }
  const failed = checks.filter((c) => !c.ok);
  const status = failed.length === 0 ? 'valid' : failed.every((c) => c.transport) ? 'indeterminate' : 'invalid';
  const officialEndpoints = endpoints.length > 0 && !!net && endpoints.every((e) => e === net.rpc);
  return { valid: status === 'valid', status, contentChecked: content !== null, endpoints, officialEndpoints, checks };
}

module.exports = { verify };
