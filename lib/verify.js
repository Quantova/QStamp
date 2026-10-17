// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { digestBytes, digestFile, parseDigest } = require('./hash');
const { leafHash, rootFromPath, commitment } = require('./merkle');
const { stampedEventData, stampedSelector, callMatches } = require('./wire');
const { validate } = require('./receipt');
const { NETWORKS } = require('./networks');
const { clientFor, read, isTransient, clean } = require('./client');
const { targetsOf, quorumProblem, labelOf } = require('./endpoints');

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
  const seen = {};
  let complete = true;
  const add = (name, ok, detail, transport) =>
    checks.push({ name: label ? name + ' @ ' + label : name, ok, detail, transport: !!transport });
  const fetch = async (name, fn) => {
    try {
      return { value: await read(fn) };
    } catch (e) {
      complete = false;
      add(name, false, 'the endpoint could not answer (' + clean((e && e.message) || e, 120) + ')', isTransient(e));
      return null;
    }
  };
  const until = receipt.until;
  const info = await fetch('chain', () => client.nodeInfo());
  if (!info) return { checks, summary: null };
  const sameChain = !!info.value && info.value.chain_id === receipt.chain.id && info.value.genesis_hash === receipt.chain.genesis;
  add('chain', sameChain, sameChain ? 'the endpoint serves the chain named in the receipt' : 'the endpoint serves a different chain');
  if (!sameChain) return { checks, summary: null };
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
      if (!callMatches(raw, anchored, receipt.kind, until)) problems.push('it does not carry this commitment');
    }
    seen.tx = tx && typeof tx === 'object'
      ? { status: tx.status, height: tx.height, block: tx.block, from: tx.from, to: tx.to, kind: tx.kind, raw: typeof tx.raw === 'string' ? tx.raw.toLowerCase() : null }
      : null;
    add('transaction', problems.length === 0,
      problems.length ? 'the anchoring transaction does not match, ' + problems.join(', ') : 'the anchoring transaction is final and carries this commitment');
  }
  const evr = await fetch('event', () => client.events(receipt.anchor.height));
  if (evr) {
    const list = evr.value && Array.isArray(evr.value.events) ? evr.value.events : [];
    const want = stampedEventData(receipt.anchor.sender, anchored, receipt.kind, until);
    const selector = stampedSelector(until);
    const found = list.some(
      (e) => e && typeof e === 'object' && e.contract === receipt.contract && e.selector === selector &&
        typeof e.data === 'string' && e.data.toLowerCase() === want,
    );
    seen.event = found;
    if (found) add('event', true, until === undefined
      ? 'the stamp contract recorded this commitment, signer and kind in that block'
      : 'the stamp contract recorded this commitment, signer, kind and deadline in that block');
    else if (evr.value && evr.value.truncated) {
      complete = false;
      add('event', false, 'the endpoint truncated the event list, so the result is inconclusive', true);
    } else add('event', false, 'no matching stamp event was recorded in that block');
  }
  const blr = await fetch('block', () => client.block(receipt.anchor.height));
  if (blr) {
    const b = blr.value;
    seen.block = b && typeof b === 'object' ? { block: b.block, height: b.height, time: b.time } : null;
    const ok = !!b && b.block === receipt.anchor.block && b.height === receipt.anchor.height && b.time === receipt.anchor.time;
    add('block', ok, ok ? 'the block id and time match the receipt' : 'the block id or time differs from the receipt');
  }
  return { checks, summary: complete ? JSON.stringify(seen) : null };
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
  let targets = null;
  let quorum = null;
  try {
    targets = targetsOf(opts, net);
    quorum = quorumProblem(targets, opts);
  } catch (e) {
    add('anchor', false, clean((e && e.message) || e, 200));
  }
  const endpoints = [];
  if (targets && targets.length === 0) {
    add('anchor', false, 'no rpc endpoint is known for this chain', true);
  } else if (targets) {
    const answers = [];
    for (let i = 0; i < targets.length; i += 1) {
      let client;
      try {
        client = clientFor(targets[i], receipt.chain.id);
      } catch (e) {
        add('anchor', false, clean((e && e.message) || e, 200));
        continue;
      }
      endpoints.push(labelOf(targets[i]));
      const label = targets.length > 1 ? String(i + 1) : '';
      answers.push(await chainChecks(client, receipt, anchored, label));
    }
    const bad = answers.filter((a) => a.checks.some((c) => !c.ok && !c.transport));
    const summaries = answers.filter((a) => a.summary !== null).map((a) => a.summary);
    const split = bad.length > 0 && bad.length < answers.length;
    if (split) for (const a of bad) for (const c of a.checks) if (!c.ok) c.transport = true;
    for (const a of answers) for (const c of a.checks) checks.push(c);
    if (answers.length > 1) {
      const agree = !split && summaries.every((x) => x === summaries[0]);
      add('agreement', agree, agree ? 'the endpoints that answered returned the same chain data' : 'the endpoints returned different chain data for this anchor, so at least one of them is dishonest and the anchor is not accepted', !agree);
    }
    if (quorum) add('endpoints', false, quorum, true);
    else if (targets.length === 1) add('endpoints', true, 'the caller chose to rely on a single endpoint');
    else add('endpoints', true, targets.length + ' independent endpoints were consulted');
  }
  const failed = checks.filter((c) => !c.ok);
  const status = failed.length === 0 ? 'valid' : failed.every((c) => c.transport) ? 'indeterminate' : 'invalid';
  const officialEndpoints = endpoints.length > 0 && !!net && endpoints.every((e) => e === net.rpc);
  return { valid: status === 'valid', status, contentChecked: content !== null, endpoints, officialEndpoints, checks };
}

module.exports = { verify };
