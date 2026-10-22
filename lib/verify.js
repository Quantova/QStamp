// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const qcore = require('@quantovainc/qcore');
const CORE_BINDS_GENESIS = (() => {
  try {
    const [major, minor] = require('@quantovainc/qcore/package.json').version.split('.').map(Number);
    return major > 0 || minor >= 8;
  } catch (e) {
    return false;
  }
})();
const { digestBytes, digestFile, parseDigest } = require('./hash');
const { leafHash, rootFromPath, commitment } = require('./merkle');
const W = require('./wire');
const { validate } = require('./receipt');
const { decode } = require('./bech32m');
const { NETWORKS, checkNetwork, requiresFinality } = require('./networks');
const { read, clean, failureCode, isTransient } = require('./client');
const { endpointsFor, readerOf, officialGroups } = require('./endpoints');
const { proveAnchor, helpersFrom, eventLeaf } = require('./finality');
const D = require('./deadline');

const FUTURE_SLACK_S = 300;
const HEAD_WALK = 16;
const DEFAULT_DEADLINE_MS = 300000;
const KEYED_BASE = 1n << 40n;
const KEYED_STRIDE = 1n << 32n;
const REVOCATION_TAGS = Object.freeze({
  [W.COMMITMENT_STAMPED_SELECTOR]: KEYED_BASE + 1n * KEYED_STRIDE,
});
const NOT_APPLICABLE = 'not applicable';
const TRUSTED = new Set(['finality-proof']);

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

function selectorsFor(receipt, custom) {
  if (receipt.until !== undefined) return [W.STAMPED_UNTIL_SELECTOR];
  return custom ? [W.STAMPED_SELECTOR, W.COMMITMENT_STAMPED_SELECTOR] : [W.STAMPED_SELECTOR];
}

function revocationApplies(selector) {
  return Object.prototype.hasOwnProperty.call(REVOCATION_TAGS, selector);
}

async function revocationOf(client, receipt, anchored, selector) {
  const tag = REVOCATION_TAGS[selector];
  const keyHex = anchored.toString('hex');
  if (typeof client.storageAt === 'function') {
    const slot = qcore.core.mapSlotKey(tag, keyHex);
    const resp = await read(() => client.storageAt(receipt.contract, [slot]));
    return { value: BigInt(qcore.core.storageValue(JSON.stringify(resp), slot)) };
  }
  if (typeof client.contractMap === 'function') {
    const v = await read(() => client.contractMap(receipt.contract, tag, keyHex));
    return { value: BigInt(v) };
  }
  return null;
}

async function headBlockTime(client, head) {
  for (let h = head; h >= 0 && h > head - HEAD_WALK; h -= 1) {
    let block;
    try {
      block = await read(() => client.block(h));
    } catch (e) {
      if (isTransient(e) || !/^(http 4[0-9][0-9]|malformed reply|error)$/.test(failureCode(e))) return null;
      continue;
    }
    if (!block) continue;
    if (block.height !== h || !Number.isSafeInteger(block.time) || block.time <= 0) return null;
    return block.time;
  }
  return null;
}

async function chainChecks(client, receipt, anchored, label, ctx) {
  const checks = [];
  const seen = {};
  let transport = false;
  let negative = false;
  let revoked = null;
  let selector = null;
  let nodeInfo = null;
  const add = (name, ok, detail, isTransport) => {
    checks.push({ name: label ? name + ' @ ' + label : name, ok, detail, transport: !!isTransport });
    if (!ok) {
      if (isTransport) transport = true;
      else negative = true;
    }
  };
  const done = () => ({
    checks,
    summary: transport ? null : JSON.stringify(seen),
    verdict: negative ? 'negative' : transport ? 'transport' : 'positive',
    revoked,
    nodeInfo,
  });
  const fetch = async (name, fn) => {
    try {
      return { value: await read(fn) };
    } catch (e) {
      add(name, false, 'the endpoint could not answer (' + failureCode(e) + ')', true);
      return null;
    }
  };
  const until = receipt.until;
  const info = await fetch('chain', () => client.nodeInfo());
  if (!info) return done();
  if (info.value && typeof info.value === 'object' && !Array.isArray(info.value)) nodeInfo = { chain_id: info.value.chain_id, genesis_hash: info.value.genesis_hash };
  const sameChain = !!info.value && info.value.chain_id === receipt.chain.id && info.value.genesis_hash === receipt.chain.genesis;
  if (!sameChain) {
    add('chain', false, 'the endpoint serves a different chain, so it cannot speak for this receipt', true);
    return done();
  }
  const head = info.value.head_height;
  if (!Number.isSafeInteger(head) || head < 0) {
    add('chain', false, 'the endpoint reported no valid head height', true);
    return done();
  }
  if (head < receipt.anchor.height) {
    const headTime = await headBlockTime(client, head);
    if (headTime !== null && headTime > receipt.anchor.time) {
      seen.head = { height: head, time: headTime };
      add('chain', false, 'the endpoint has not reached the height of the anchor, yet its head block is already later than the anchor time, so no block at the anchor height can carry that time');
    } else {
      add('chain', false, 'the endpoint has not reached the height of the anchor', true);
    }
    return done();
  }
  add('chain', true, 'the endpoint serves the chain named in the receipt');
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
      const carries = ctx.custom ? W.carriesCommitment(raw, anchored) : W.callMatches(raw, anchored, receipt.kind, until);
      if (!carries) problems.push('it does not carry this commitment');
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
    const hit = list.find(
      (e) => e && typeof e === 'object' && e.contract === receipt.contract && ctx.selectors.includes(e.selector) &&
        typeof e.data === 'string' && e.data.toLowerCase() === ctx.data,
    );
    seen.event = hit ? hit.selector : false;
    if (hit) {
      selector = hit.selector;
      add('event', true, until === undefined
        ? 'the stamp contract recorded this commitment, signer and kind in that block'
        : 'the stamp contract recorded this commitment, signer, kind and deadline in that block');
    } else if (evr.value && evr.value.truncated) {
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
  if (ctx.custom && selector !== null && !revocationApplies(selector)) {
    revoked = NOT_APPLICABLE;
    seen.revoked = NOT_APPLICABLE;
    add('revocation', true, 'the contract recorded this stamp with an event that has no withdrawal map, so withdrawal does not apply');
  } else if (ctx.custom && selector !== null) {
    try {
      const r = await revocationOf(client, receipt, anchored, selector);
      if (r === null) {
        add('revocation', false, 'the endpoint cannot read contract state, so a withdrawal by the issuer could not be ruled out', true);
      } else if (r.value !== 0n) {
        revoked = { reason: r.value.toString() };
        seen.revoked = revoked.reason;
        add('revocation', false, 'the issuer withdrew this commitment with reason code ' + r.value.toString());
      } else {
        revoked = false;
        seen.revoked = '0';
        add('revocation', true, 'the issuer has not withdrawn this commitment');
      }
    } catch (e) {
      add('revocation', false, 'the endpoint could not answer (' + failureCode(e) + ')', true);
    }
  }
  return done();
}

function pinContract(net, opts, receipt, add) {
  const custom = opts.trustCustomContract === true;
  if (net) {
    if (opts.contract !== undefined && opts.contract !== net.contract && !custom) {
      add('contract', false, 'a contract other than the official one was requested without trustCustomContract');
      return false;
    }
    const pinned = custom && opts.contract !== undefined ? opts.contract : net.contract;
    const official = pinned === net.contract;
    add('contract', pinned === receipt.contract, pinned !== receipt.contract
      ? 'the receipt names an unrecognised contract'
      : official ? 'the receipt names the official stamp contract' : 'the receipt names the contract the caller chose to trust');
    return !official;
  }
  if (custom && typeof opts.contract === 'string') {
    add('contract', opts.contract === receipt.contract, opts.contract === receipt.contract
      ? 'the receipt names the contract the caller chose to trust' : 'the receipt names an unrecognised contract');
    return true;
  }
  add('contract', false, 'the receipt names a chain this release does not know, pass contract with trustCustomContract to accept it');
  return true;
}

function expectedSenders(opts) {
  if (opts.expectedSender === undefined) return null;
  const list = Array.isArray(opts.expectedSender) ? opts.expectedSender : [opts.expectedSender];
  if (list.length === 0 || list.length > 64) throw new Error('expectedSender is an address or a short list of addresses');
  for (const a of list) {
    try {
      if (typeof a !== 'string') throw new Error('type');
      decode(a, 'Q', 32);
    } catch (e) {
      throw new Error('expectedSender must hold Q1 addresses');
    }
  }
  return list.map((a) => a.toUpperCase());
}

function plausibility(net, receipt, add) {
  const t = receipt.anchor.time;
  const h = receipt.anchor.height;
  const problems = [];
  if (net && (!Number.isSafeInteger(net.genesisTime) || !net.blocks)) {
    problems.push('the network gives no bounds for the height of its chain, so the anchor height cannot be checked');
  } else if (net) {
    if (t < net.genesisTime) {
      problems.push('the anchor time is before the genesis of the chain');
    } else {
      const elapsed = t - net.genesisTime;
      const most = elapsed * net.blocks.maxPerSecond + net.blocks.slack;
      const least = Math.max(0, elapsed - net.blocks.stallSeconds) * net.blocks.minPerSecond - net.blocks.slack;
      if (h > most) problems.push('the anchor height is higher than the chain can have reached by the anchor time');
      if (h < least) problems.push('the anchor height is lower than the chain had certainly reached by the anchor time');
    }
  }
  add('plausibility', problems.length === 0, problems.length
    ? problems.join(', ')
    : net ? 'the anchor time and height are consistent with the history of the chain' : 'the anchor time and height were not bounded, since the network is not known');
}

function clockCheck(receipt) {
  const ahead = receipt.anchor.time > Math.floor(Date.now() / 1000) + FUTURE_SLACK_S;
  return {
    name: 'clock',
    ok: !ahead,
    detail: ahead
      ? 'the anchor time lies more than five minutes ahead of the clock of this computer, so either this clock is slow or the receipt names a time the chain has not reached, and only a verified finality certificate can settle which'
      : 'the anchor time is not ahead of the clock of this computer',
    transport: ahead,
  };
}

function names(answers) {
  return answers.map((a) => clean(a.entry.label, 80)).join(', ');
}

function operatorOf(entry) {
  if (entry.operator) return entry.operator;
  const domain = [...entry.keys].find((k) => k.startsWith('domain:'));
  return domain ? domain.slice(7) : entry.host;
}

const ISSUED = new WeakSet();
const RECEIPT_TEXT_MAX = 65536;

function issued(result) {
  ISSUED.add(result);
  return result;
}

function isProven(result) {
  return !!result && typeof result === 'object' && ISSUED.has(result) && result.status === 'valid' && result.valid === true &&
    result.proven === true && TRUSTED.has(result.trust);
}

function refused(name, e) {
  return {
    valid: false,
    status: 'indeterminate',
    proven: false,
    trust: 'none',
    trustDetail: '',
    revoked: null,
    contentChecked: false,
    endpoints: [],
    officialEndpoints: false,
    operators: [],
    notices: [],
    checks: [{ name, ok: false, detail: clean((e && e.message) || e, 300), transport: true }],
  };
}

async function verifyWith(netOverride, input, options, deps) {
  let ctl;
  try {
    ctl = D.controlOf(options, Infinity);
  } catch (e) {
    return refused('options', e);
  }
  try {
    return await D.runWith(ctl, () => verifyIn(netOverride, input, options, deps));
  } catch (e) {
    return refused('verification', e);
  }
}

async function verifyIn(netOverride, input, options, deps) {
  const opts = Object.assign(Object.create(null), options);
  const extra = deps || {};
  const checks = [];
  const notices = [];
  const add = (name, ok, detail, transport) => checks.push({ name, ok, detail, transport: !!transport });
  const outcome = (status, fields) => issued(Object.assign({
    valid: status === 'valid',
    status,
    proven: false,
    trust: 'none',
    trustDetail: '',
    revoked: null,
    contentChecked: false,
    endpoints: [],
    officialEndpoints: false,
    operators: [],
    notices,
    checks,
  }, fields || {}, { valid: status === 'valid', status }));
  const fromEndpoint = new Set();
  const out = (status, fields) => {
    if (status !== 'valid' && status !== 'invalid') {
      for (let i = 0; i < checks.length; i += 1) {
        const c = checks[i];
        if (!c.ok && !c.transport && fromEndpoint.has(c)) {
          checks[i] = { name: c.name, ok: false, detail: c.detail + ', as an endpoint reported it, and neither a verified finality certificate nor official endpoints of two different operators confirmed it, so it does not refute the receipt', transport: true };
        }
      }
    }
    if (status !== 'valid' && !checks.some((c) => !c.ok)) {
      checks.push({ name: 'result', ok: false, detail: 'the receipt is reported ' + status + ', so it is neither confirmed nor relied on', transport: status !== 'invalid' });
    }
    return outcome(status, fields);
  };
  let receipt;
  try {
    if (!input || typeof input !== 'object' || Array.isArray(input) || ArrayBuffer.isView(input) || input instanceof ArrayBuffer) throw new Error('a receipt is a JSON object');
    const text = JSON.stringify(input);
    if (typeof text !== 'string' || text.length > RECEIPT_TEXT_MAX) throw new Error('a receipt is at most ' + RECEIPT_TEXT_MAX + ' characters of JSON');
    receipt = JSON.parse(text, (k, v) => (v && typeof v === 'object' && !Array.isArray(v) ? Object.assign(Object.create(null), v) : v));
    validate(receipt);
  } catch (e) {
    add('format', false, clean((e && e.message) || e, 300));
    return out('invalid');
  }
  add('format', true, 'the receipt is well formed');
  if (netOverride) {
    try {
      checkNetwork(netOverride, opts);
    } catch (e) {
      add('network', false, clean((e && e.message) || e, 300), true);
      return out('indeterminate');
    }
  }
  const net = netOverride || networkFor(receipt);
  const needsProof = requiresFinality(net);
  const custom = pinContract(net, opts, receipt, add);
  let content = null;
  let unreadable = false;
  try {
    content = await contentDigest(receipt, opts);
  } catch (e) {
    if (D.isStop(e)) {
      add('content', false, 'the content was not read in full before the deadline passed or the signal aborted', true);
      return out('indeterminate');
    }
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
  let root;
  try {
    const leaf = leafHash(receipt.record.alg, Buffer.from(receipt.record.digest, 'hex'), Buffer.from(receipt.record.salt, 'hex'));
    root = Buffer.from(receipt.root, 'hex');
    const computed = rootFromPath(leaf, receipt.proof.index, receipt.proof.size, receipt.proof.path.map((p) => Buffer.from(p, 'hex')));
    const included = !!computed && computed.equals(root);
    add('inclusion', included, included ? 'the fingerprint is included in the batch root' : 'the inclusion path does not lead to the batch root');
  } catch (e) {
    add('inclusion', false, 'the inclusion path could not be evaluated');
    return out('invalid');
  }
  try {
    const senders = expectedSenders(opts);
    if (senders) {
      const ok = senders.includes(receipt.anchor.sender);
      add('sender', ok, ok ? 'the anchor was signed by an expected issuer' : 'the anchor was signed by an account that is not an expected issuer for this record');
    }
  } catch (e) {
    add('sender', false, clean(e.message, 200));
  }
  plausibility(net, receipt, add);
  const clock = clockCheck(receipt);
  checks.push(clock);
  const intrinsicFailure = checks.some((c) => !c.ok && !c.transport);
  let anchored;
  let data;
  const selectors = selectorsFor(receipt, custom);
  try {
    anchored = commitment(root, receipt.proof.size, {
      genesis: receipt.chain.genesis, contract: receipt.contract, sender: receipt.anchor.sender, kind: receipt.kind,
    });
    data = W.stampedEventData(receipt.anchor.sender, anchored, receipt.kind, receipt.until);
  } catch (e) {
    add('commitment', false, 'the commitment of the receipt could not be computed');
    return out('invalid');
  }
  const ctx = { custom, selectors, data };
  if (opts.deadlineMs === undefined) D.startClock(DEFAULT_DEADLINE_MS);
  let plan = null;
  try {
    plan = await endpointsFor(opts, net, 'verify');
  } catch (e) {
    add('endpoints', false, clean((e && e.message) || e, 300), true);
  }
  if (plan && plan.refused) {
    add('endpoints', false, plan.refused, true);
    plan = null;
  }
  if (plan && plan.entries.length === 0) {
    add('endpoints', false, 'no rpc endpoint is known for this chain', true);
    plan = null;
  }
  const contentChecked = content !== null;
  if (!plan) return out(intrinsicFailure ? 'invalid' : 'indeterminate', { contentChecked });
  const answers = [];
  for (let i = 0; i < plan.entries.length; i += 1) {
    const entry = plan.entries[i];
    const client = readerOf(entry);
    const label = plan.entries.length > 1 ? String(i + 1) : '';
    answers.push(Object.assign(await chainChecks(client, receipt, anchored, label, ctx), { entry, client }));
  }
  const endpoints = plan.entries.map((e) => e.label);
  const officialEndpoints = plan.entries.every((e) => e.official);
  const operators = [...new Set(plan.entries.map(operatorOf))];
  const base = { contentChecked, endpoints, officialEndpoints, operators };
  const proof = await proveAnchor({
    net,
    receipt,
    helpers: extra.helpers || (CORE_BINDS_GENESIS ? helpersFrom(qcore) : {}),
    sources: answers.map((a) => ({ client: a.client, label: a.entry.label, info: a.nodeInfo })),
    leaf: selectors.map((sel) => eventLeaf(receipt.contract, sel, data)),
    selectors,
    data,
    anchored,
    custom,
  });
  const endpointChecks = answers.flatMap((a) => a.checks);
  for (const c of endpointChecks) fromEndpoint.add(c);
  const negatives = answers.filter((a) => a.verdict === 'negative');
  const positives = answers.filter((a) => a.verdict === 'positive');
  const officialOf = (list) => officialGroups(list.filter((a) => a.entry.official).map((a) => a.entry));
  const revokers = answers.filter((a) => a.revoked && typeof a.revoked === 'object' && a.revoked.reason);
  const revokedBy = revokers[0];
  const revocationConfirmed = revokers.length > 0 && officialOf(revokers).length >= 2 && !answers.some((a) => a.revoked === false) &&
    new Set(revokers.map((a) => a.revoked.reason)).size === 1;
  const denialConfirmed = negatives.length > 0 && positives.length === 0 && officialOf(negatives).length >= 2;
  const describeGroups = (n) => n + (n === 1 ? ' endpoint was' : ' endpoints were') + ' consulted, run by ' + plan.groups.length + (plan.groups.length === 1 ? ' operator' : ' independent operators');
  const officialPositive = officialGroups(positives.map((a) => a.entry));
  const quorumAgrees = officialPositive.length >= 2 && new Set(positives.filter((a) => a.entry.official).map((a) => a.summary)).size === 1;
  const notWithdrawn = (a) => a.revoked === false || a.revoked === NOT_APPLICABLE;
  const provenWithoutMap = proof.state === 'proven' && !revocationApplies(proof.selector);
  const revocationSettled = !custom || (!revokedBy && (provenWithoutMap || (quorumAgrees && positives.filter((a) => a.entry.official).every(notWithdrawn))));
  const revokedField = (applies) => (custom && applies ? false : null);
  if (intrinsicFailure || revocationConfirmed || proof.state === 'refuted') {
    for (const c of endpointChecks) checks.push(c);
    if (proof.state === 'refuted') add('finality', false, proof.detail);
    return out('invalid', Object.assign(base, { revoked: revocationConfirmed ? revokedBy.revoked : null }));
  }
  if (revokedBy) {
    for (const c of endpointChecks) checks.push(c);
    add('revocation', false, names(revokers) + ' reported that the issuer withdrew this commitment, but the withdrawal was not confirmed alike by official endpoints of two different operators, so the receipt is neither confirmed nor refuted', true);
    return out('indeterminate', base);
  }
  if (proof.state === 'proven') {
    const txProven = proof.transaction === 'proven';
    const disputed = txProven ? [] : endpointChecks.filter((c) => !c.ok && !c.transport && /^transaction( @ |$)/.test(c.name));
    for (const c of endpointChecks) {
      if (c.ok || disputed.includes(c)) checks.push(c);
      else notices.push(c.name + ', ' + c.detail);
    }
    if (!clock.ok) {
      checks[checks.indexOf(clock)] = { name: 'clock', ok: true, detail: 'the anchor time lies ahead of the clock of this computer, but a verified finality certificate fixes the block at that time, so this clock is behind the chain', transport: false };
    }
    add('finality', true, proof.detail);
    const confirmed = endpointChecks.some((c) => c.ok && /^transaction( @ |$)/.test(c.name));
    if (!txProven && proof.transaction === 'unproved') {
      add('transaction', false, 'the anchoring transaction is covered neither by a transaction inclusion proof that holds nor by an endpoint that may be relied on, so the receipt is neither confirmed nor refuted', true);
      return out('indeterminate', Object.assign(base, { trust: 'finality-proof', trustDetail: proof.detail + ', but ' + clean(proof.transactionDetail, 200) + ', and an endpoint that serves a proof that does not hold is not relied on to confirm the transaction, so the receipt is neither confirmed nor refuted' }));
    }
    if (!txProven && (disputed.length > 0 || !confirmed)) {
      const why = disputed.length > 0 ? 'an endpoint reported that the transaction does not match' : 'no endpoint confirmed the transaction';
      add('transaction', false, 'the anchoring transaction is not covered by a transaction inclusion proof and ' + why + ', so the receipt is neither confirmed nor refuted', true);
      return out('indeterminate', Object.assign(base, { trust: 'finality-proof', trustDetail: proof.detail + ', but ' + clean(proof.transactionDetail || 'no endpoint served a transaction inclusion proof', 160) + ', so the transaction id in the receipt is not covered by the proof, and ' + why + ', so the receipt is neither confirmed nor refuted' }));
    }
    if (!revocationSettled) {
      add('proof', false, 'the anchor is proven by a finality certificate, but whether the issuer withdrew it was not confirmed by official endpoints of two different operators, so the receipt is not reported valid', true);
      return out('unproven', Object.assign(base, { trust: 'finality-proof', trustDetail: proof.detail + ', the withdrawal state of the issuer contract is not covered by the proof', revoked: revokedBy ? null : false }));
    }
    return out('valid', Object.assign(base, { proven: true, trust: 'finality-proof', trustDetail: proof.detail, revoked: revokedField(revocationApplies(proof.selector)) }));
  }
  for (const c of endpointChecks) checks.push(c);
  if (proof.state === 'failed') notices.push(proof.detail);
  if (denialConfirmed) return out('invalid', base);
  if (negatives.length > 0 && positives.length === 0) {
    add('agreement', false, names(negatives) + ' reported that the anchor does not match the chain, but neither a verified finality certificate nor official endpoints of two different operators confirmed it, so the receipt is neither confirmed nor refuted', true);
    return out('indeterminate', base);
  }
  if (negatives.length > 0) {
    add('agreement', false, 'the endpoints disagree about this anchor, ' + names(negatives) + ' reported that it does not match the chain while ' + names(positives) + ' reported that it does, and no verified finality certificate settles it, so the receipt is neither confirmed nor refuted', true);
    return out('indeterminate', base);
  }
  if (positives.length > 1 && new Set(positives.map((a) => a.summary)).size > 1) {
    add('agreement', false, 'the endpoints ' + names(positives) + ' returned different chain data for this anchor, so at least one of them is dishonest, and no verified finality certificate settles it, so the receipt is neither confirmed nor refuted', true);
    return out('indeterminate', base);
  }
  if (positives.length === 0) return out('indeterminate', base);
  if (positives.length > 1) add('agreement', true, 'the endpoints that answered returned the same chain data');
  if (quorumAgrees && revocationSettled && needsProof) {
    const ops = officialPositive.map((g) => operatorOf(g[0])).join(', ');
    const trustDetail = 'official endpoints run by ' + officialPositive.length + ' different operators confirmed the anchor (' + clean(ops, 200) + '), but this network accepts an anchor only through a finality proof, and ' + proof.detail;
    add('proof', false, 'the anchor is not proven, ' + trustDetail, true);
    return out(proof.state === 'failed' ? 'indeterminate' : 'unproven', Object.assign(base, { trust: 'none', trustDetail }));
  }
  if (quorumAgrees && revocationSettled) {
    const ops = officialPositive.map((g) => operatorOf(g[0])).join(', ');
    add('endpoints', true, 'official endpoints run by ' + officialPositive.length + ' different operators confirmed the anchor (' + clean(ops, 200) + ')');
    const trustDetail = 'the anchor was confirmed by official endpoints run by ' + officialPositive.length + ' different operators, ' + clean(ops, 200) + ', but agreeing endpoints are not a cryptographic proof, and ' + proof.detail;
    add('proof', false, 'the anchor is not proven, ' + trustDetail, true);
    return out(proof.state === 'failed' ? 'indeterminate' : 'unproven', Object.assign(base, {
      trust: 'official-quorum',
      trustDetail,
      revoked: revokedField(positives.some((a) => a.revoked === false)),
    }));
  }
  const transportLeft = answers.some((a) => a.verdict === 'transport');
  if (transportLeft && officialGroups(plan.entries).length >= 2) {
    add('endpoints', false, 'not every official endpoint answered, so the anchor could not be confirmed by two operators', true);
    return out('indeterminate', base);
  }
  const viaCustom = positives.some((a) => !a.entry.official);
  const trust = viaCustom ? 'custom-endpoints' : 'single-endpoint';
  const who = names(positives);
  const trustDetail = viaCustom
    ? 'the anchor matches what endpoints chosen by the caller reported (' + who + '), they are not official endpoints of this network and could have invented it together'
    : 'the anchor matches what one operator reported (' + clean(operators.join(', '), 120) + '), a dishonest operator could have invented it alone';
  add('endpoints', true, describeGroups(plan.entries.length));
  add('proof', false, 'the anchor is not proven, ' + trustDetail + ', and ' + proof.detail, true);
  return out('unproven', Object.assign(base, { trust, trustDetail, revoked: custom ? (positives.every((a) => a.revoked === false) ? false : null) : null }));
}

const VERIFY_OPTIONS = new Set(['file', 'bytes', 'digest', 'contract', 'trustCustomContract', 'expectedSender', 'rpc', 'client', 'clients', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'deadlineMs', 'signal']);

function verify(input, options) {
  if (options !== undefined && options !== null) {
    if (typeof options !== 'object' || Array.isArray(options) || ArrayBuffer.isView(options)) return Promise.resolve(refused('options', new Error('the options of verify are a plain object')));
    let keys;
    try {
      keys = Object.keys(options);
    } catch (e) {
      return Promise.resolve(refused('options', new Error('the options of verify could not be read')));
    }
    const unknown = keys.find((k) => !VERIFY_OPTIONS.has(k));
    if (unknown !== undefined) return Promise.resolve(refused('options', new Error('the option ' + unknown.replace(/[^A-Za-z0-9_]/g, '?').slice(0, 40) + ' is not an option of verify, so nothing was checked')));
  }
  return verifyWith(null, input, Object.assign(Object.create(null), options), null);
}

module.exports = { verify, verifyWith, isProven, REVOCATION_TAGS };
