// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32M_CONST = 0x2bc830a3;
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const MAX_ENCODED = 128;

function polymod(values) {
  let chk = 1;
  for (const value of values) {
    const top = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ value) >>> 0;
    for (let bit = 0; bit < 5; bit += 1) {
      if ((top >>> bit) & 1) chk = (chk ^ GENERATOR[bit]) >>> 0;
    }
  }
  return chk >>> 0;
}

function hrpExpand(hrp) {
  const lowered = hrp.toLowerCase();
  const out = [];
  for (let i = 0; i < lowered.length; i += 1) out.push(lowered.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < lowered.length; i += 1) out.push(lowered.charCodeAt(i) & 31);
  return out;
}

function convertBits(data, from, to, pad) {
  let acc = 0;
  let bits = 0;
  const maxValue = (1 << to) - 1;
  const maxAcc = (1 << (from + to - 1)) - 1;
  const out = [];
  for (const value of data) {
    if (value < 0 || value >> from !== 0) return null;
    acc = ((acc << from) | value) & maxAcc;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxValue);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxValue);
  } else if (bits >= from || ((acc << (to - bits)) & maxValue) !== 0) {
    return null;
  }
  return out;
}

function decode(text, expectedHrp, expectedLength) {
  if (typeof text !== 'string' || text.length === 0) throw new Error('the identifier is empty');
  if (text.length > MAX_ENCODED) throw new Error('the identifier is too long');
  const hasLower = /[a-z]/.test(text);
  const hasUpper = /[A-Z]/.test(text);
  if (hasLower && hasUpper) throw new Error('the identifier mixes upper and lower case');
  const lowered = text.toLowerCase();
  const separator = lowered.lastIndexOf('1');
  if (separator < 1 || separator + 7 > lowered.length) throw new Error('the identifier has no separator');
  const hrp = lowered.slice(0, separator);
  for (let i = 0; i < hrp.length; i += 1) {
    const code = hrp.charCodeAt(i);
    if (code < 33 || code > 126) throw new Error('the identifier prefix holds a bad character');
  }
  if (hrp !== expectedHrp.toLowerCase()) throw new Error('the identifier carries the wrong prefix');
  const groups = [];
  for (const ch of lowered.slice(separator + 1)) {
    const index = CHARSET.indexOf(ch);
    if (index < 0) throw new Error('the identifier holds a character outside the alphabet');
    groups.push(index);
  }
  if (polymod(hrpExpand(hrp).concat(groups)) !== BECH32M_CONST) {
    throw new Error('the identifier checksum does not verify');
  }
  const payload = convertBits(groups.slice(0, groups.length - 6), 5, 8, false);
  if (payload === null) throw new Error('the identifier does not decode to whole bytes');
  if (expectedLength !== undefined && payload.length !== expectedLength) {
    throw new Error('the identifier does not hold ' + expectedLength + ' bytes');
  }
  return Buffer.from(payload);
}

function addressBytes(address) {
  return decode(address, 'Q', 32);
}

module.exports = { decode, addressBytes };
