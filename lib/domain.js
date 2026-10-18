// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { decode } = require('./bech32m');

const U64_MAX = (1n << 64n) - 1n;
const LEDGER_FORMAT = 'qstamp-deployment-domains/1';
const MAX_LEDGER_BYTES = 4 * 1024 * 1024;
const MAX_ENTRIES = 10000;
const DIGITS = /^[1-9][0-9]{0,19}$/;
const GENESIS = /^[0-9a-f]{64}$/;

function deploymentDomain() {
  for (;;) {
    const value = crypto.randomBytes(8).readBigUInt64BE(0);
    if (value !== 0n) return value.toString(10);
  }
}

function checkDomain(domain) {
  const text = typeof domain === 'bigint' ? domain.toString(10) : domain;
  if (typeof text !== 'string' || !DIGITS.test(text) || BigInt(text) > U64_MAX) {
    throw new Error('a deployment domain is a whole number from 1 to 18446744073709551615 written in decimal');
  }
  return text;
}

function checkContract(contract) {
  try {
    if (typeof contract !== 'string') throw new Error('type');
    decode(contract, 'Q', 32);
  } catch (e) {
    throw new Error('the contract is not a Quantova address');
  }
  return contract.toUpperCase();
}

function checkGenesis(genesis) {
  if (typeof genesis !== 'string' || !GENESIS.test(genesis)) throw new Error('the genesis hash must be 64 lowercase hexadecimal characters');
  return genesis;
}

function readLedger(file) {
  let text;
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile()) throw new Error('the domain ledger is not a regular file');
    if (stat.size > MAX_LEDGER_BYTES) throw new Error('the domain ledger is too large');
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    if (e && e.code === 'ENOENT') return { format: LEDGER_FORMAT, deployments: [] };
    throw e;
  }
  let ledger;
  try {
    ledger = JSON.parse(text);
  } catch (e) {
    throw new Error('the domain ledger is not valid JSON');
  }
  if (!ledger || typeof ledger !== 'object' || ledger.format !== LEDGER_FORMAT || !Array.isArray(ledger.deployments) || ledger.deployments.length > MAX_ENTRIES) {
    throw new Error('the domain ledger is not a ' + LEDGER_FORMAT + ' file');
  }
  for (const d of ledger.deployments) {
    if (!d || typeof d !== 'object') throw new Error('the domain ledger holds a malformed entry');
    checkContract(d.contract);
    checkGenesis(d.genesis);
    checkDomain(d.domain);
  }
  return ledger;
}

function recordDomain(file, entry) {
  if (typeof file !== 'string' || file.length === 0) throw new Error('give the path of the domain ledger');
  const e = entry || {};
  const contract = checkContract(e.contract);
  const genesis = checkGenesis(e.genesis);
  const domain = e.domain === undefined ? deploymentDomain() : checkDomain(e.domain);
  const ledger = readLedger(file);
  for (const d of ledger.deployments) {
    if (d.contract.toUpperCase() !== contract) continue;
    if (d.domain === domain) {
      throw new Error('the domain ' + domain + ' is already recorded for the contract ' + contract + ', so orders signed for that deployment would be accepted again, draw a fresh domain with qstamp domain');
    }
    if (d.genesis === genesis) {
      throw new Error('a deployment of the contract ' + contract + ' on this genesis is already recorded');
    }
  }
  if (ledger.deployments.length >= MAX_ENTRIES) throw new Error('the domain ledger is full');
  const record = { contract, genesis, domain, recorded: new Date().toISOString() };
  const next = { format: LEDGER_FORMAT, deployments: ledger.deployments.concat([record]) };
  const tmp = path.join(path.dirname(path.resolve(file)), '.' + path.basename(file) + '.' + crypto.randomBytes(6).toString('hex') + '.tmp');
  try {
    fs.writeFileSync(tmp, JSON.stringify(next, null, 2) + '\n', { flag: 'wx' });
    fs.renameSync(tmp, file);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
  return record;
}

module.exports = { deploymentDomain, recordDomain, readLedger, checkDomain, LEDGER_FORMAT };
