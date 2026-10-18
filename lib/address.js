// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const MULTI_LABEL_SUFFIXES = new Set([
  'ac.uk', 'co.uk', 'gov.uk', 'ltd.uk', 'me.uk', 'net.uk', 'nhs.uk', 'org.uk', 'plc.uk', 'police.uk', 'sch.uk',
  'asn.au', 'com.au', 'edu.au', 'gov.au', 'id.au', 'net.au', 'org.au',
  'ac.nz', 'co.nz', 'geek.nz', 'gen.nz', 'govt.nz', 'net.nz', 'org.nz', 'school.nz',
  'ac.jp', 'co.jp', 'ed.jp', 'go.jp', 'gr.jp', 'lg.jp', 'ne.jp', 'or.jp',
  'ac.kr', 'co.kr', 'go.kr', 'ne.kr', 'or.kr', 're.kr',
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
  'com.hk', 'net.hk', 'org.hk', 'gov.hk', 'edu.hk', 'idv.hk',
  'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg', 'per.sg',
  'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my',
  'com.tw', 'net.tw', 'org.tw', 'gov.tw', 'edu.tw', 'idv.tw',
  'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in', 'ind.in', 'gov.in', 'ac.in', 'edu.in',
  'co.za', 'net.za', 'org.za', 'gov.za', 'ac.za', 'web.za',
  'com.mx', 'net.mx', 'org.mx', 'gob.mx', 'edu.mx',
  'com.ar', 'net.ar', 'org.ar', 'gob.ar', 'edu.ar',
  'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr',
  'co.id', 'or.id', 'web.id', 'go.id', 'ac.id', 'my.id',
  'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'edu.ph',
  'com.vn', 'net.vn', 'org.vn', 'gov.vn', 'edu.vn',
  'co.th', 'in.th', 'or.th', 'go.th', 'ac.th',
  'co.il', 'org.il', 'net.il', 'gov.il', 'ac.il',
  'com.sa', 'net.sa', 'org.sa', 'gov.sa', 'edu.sa',
  'com.eg', 'net.eg', 'org.eg', 'gov.eg', 'edu.eg',
  'com.ua', 'net.ua', 'org.ua', 'gov.ua', 'in.ua',
  'com.pl', 'net.pl', 'org.pl', 'gov.pl', 'edu.pl',
  'com.pk', 'net.pk', 'org.pk', 'gov.pk', 'edu.pk',
  'com.ng', 'net.ng', 'org.ng', 'gov.ng', 'edu.ng',
  'co.ke', 'or.ke', 'go.ke', 'ac.ke',
  'com.co', 'net.co', 'nom.co', 'org.co', 'gov.co', 'edu.co',
  'com.pe', 'net.pe', 'org.pe', 'gob.pe', 'edu.pe',
  'com.ru', 'net.ru', 'org.ru', 'msk.ru', 'spb.ru',
  'com.es', 'nom.es', 'org.es', 'gob.es', 'edu.es',
  'co.at', 'or.at', 'gv.at', 'ac.at',
  'com.de', 'com.fr', 'asso.fr', 'gouv.fr',
  'com.gr', 'net.gr', 'org.gr', 'gov.gr', 'edu.gr',
  'com.pt', 'org.pt', 'gov.pt', 'edu.pt',
  'co.ae', 'net.ae', 'org.ae', 'gov.ae', 'ac.ae',
  'com.qa', 'net.qa', 'org.qa', 'gov.qa', 'edu.qa',
  'com.kw', 'net.kw', 'org.kw', 'gov.kw', 'edu.kw',
  'com.bd', 'net.bd', 'org.bd', 'gov.bd', 'edu.bd',
  'com.np', 'net.np', 'org.np', 'gov.np', 'edu.np',
  'com.lk', 'net.lk', 'org.lk', 'gov.lk', 'edu.lk',
  'co.tz', 'or.tz', 'go.tz', 'ac.tz',
  'co.ug', 'or.ug', 'go.ug', 'ac.ug',
  'com.gh', 'org.gh', 'gov.gh', 'edu.gh',
  'co.zw', 'org.zw', 'gov.zw', 'ac.zw',
  'com.cy', 'net.cy', 'org.cy', 'gov.cy',
  'com.mt', 'net.mt', 'org.mt', 'gov.mt', 'edu.mt',
]);

const WILDCARD_SERVICES = new Set([
  'nip.io', 'sslip.io', 'xip.io', 'traefik.me', 'localtest.me', 'lvh.me', 'vcap.me', 'lacolhost.com', 'nip.direct',
]);

const LOOPBACK_ADDRESSES = Object.freeze(['127.0.0.1', '0:0:0:0:0:0:0:1']);

function v4Bytes(text) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!m) return null;
  const bytes = [m[1], m[2], m[3], m[4]].map(Number);
  if (bytes.some((b) => b > 255)) return null;
  return bytes;
}

function v6Bytes(input) {
  let text = input;
  if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1);
  if (!text.includes(':') || text.includes('%')) return null;
  let tail = [];
  const lastColon = text.lastIndexOf(':');
  const last = text.slice(lastColon + 1);
  if (last.includes('.')) {
    const v4 = v4Bytes(last);
    if (!v4) return null;
    tail = v4;
    text = text.slice(0, lastColon + 1) + '0:0';
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const parse = (part) => (part === '' ? [] : part.split(':'));
  const head = parse(halves[0]);
  const rest = halves.length === 2 ? parse(halves[1]) : [];
  const groups = halves.length === 2 ? head.concat(new Array(8 - head.length - rest.length).fill('0'), rest) : head;
  if (groups.length !== 8 || head.length + rest.length > (halves.length === 2 ? 7 : 8)) return null;
  const out = [];
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    const v = parseInt(g, 16);
    out.push(v >> 8, v & 0xff);
  }
  if (tail.length) out.splice(12, 4, ...tail);
  return out;
}

function embeddedV4(bytes) {
  const zero = (from, to) => bytes.slice(from, to).every((b) => b === 0);
  if (zero(0, 10) && bytes[10] === 0xff && bytes[11] === 0xff) return bytes.slice(12, 16);
  if (zero(0, 12) && !(zero(12, 15) && bytes[15] <= 1)) return bytes.slice(12, 16);
  if (zero(0, 8) && bytes[8] === 0xff && bytes[9] === 0xff && zero(10, 12)) return bytes.slice(12, 16);
  if (bytes[0] === 0x00 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b && zero(4, 12)) return bytes.slice(12, 16);
  if (bytes[0] === 0x20 && bytes[1] === 0x02) return bytes.slice(2, 6);
  return null;
}

function parseIp(text) {
  if (typeof text !== 'string' || text.length === 0) return null;
  const v4 = v4Bytes(text);
  if (v4) return { version: 4, bytes: v4 };
  const v6 = v6Bytes(text);
  if (!v6) return null;
  const inner = embeddedV4(v6);
  if (inner) return { version: 4, bytes: inner };
  return { version: 6, bytes: v6 };
}

function ipString(ip) {
  if (ip.version === 4) return ip.bytes.join('.');
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(((ip.bytes[i] << 8) | ip.bytes[i + 1]).toString(16));
  return groups.join(':');
}

function normaliseIp(text) {
  const ip = parseIp(text);
  return ip ? ipString(ip) : null;
}

function classify(text) {
  const ip = parseIp(text);
  if (!ip) return 'invalid';
  const b = ip.bytes;
  if (ip.version === 4) {
    if (b[0] === 0) return 'unspecified';
    if (b[0] === 127) return 'loopback';
    if (b[0] === 10) return 'private';
    if (b[0] === 100 && b[1] >= 64 && b[1] <= 127) return 'private';
    if (b[0] === 172 && b[1] >= 16 && b[1] <= 31) return 'private';
    if (b[0] === 192 && b[1] === 168) return 'private';
    if (b[0] === 169 && b[1] === 254) return 'linklocal';
    if (b[0] === 192 && b[1] === 0 && b[2] === 0) return 'reserved';
    if (b[0] === 198 && (b[1] === 18 || b[1] === 19)) return 'reserved';
    if (b[0] >= 224 && b[0] <= 239) return 'multicast';
    if (b[0] >= 240) return 'reserved';
    return 'public';
  }
  if (b.every((x) => x === 0)) return 'unspecified';
  if (b.slice(0, 15).every((x) => x === 0) && b[15] === 1) return 'loopback';
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && b[4] === 0x00 && b[5] === 0x01) return 'reserved';
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && b[3] === 0x00) return 'reserved';
  if ((b[0] & 0xfe) === 0xfc) return 'private';
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return 'linklocal';
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) return 'private';
  if (b[0] === 0xff) return 'multicast';
  return 'public';
}

function hostOf(url) {
  return new URL(url).hostname.toLowerCase().replace(/\.$/, '');
}

function isLoopbackName(host) {
  return host === 'localhost' || host.endsWith('.localhost');
}

function embeddedIps(host) {
  if (parseIp(host)) return [];
  const labels = host.split('.');
  const out = new Set();
  for (let i = 0; i + 4 <= labels.length; i += 1) {
    const ip = v4Bytes(labels.slice(i, i + 4).join('.'));
    if (ip) out.add(ip.join('.'));
  }
  for (const label of labels) {
    const dashed = /(?:^|-)(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})$/.exec(label);
    if (dashed) {
      const ip = v4Bytes(dashed.slice(1, 5).join('.'));
      if (ip) out.add(ip.join('.'));
    }
    const hex = /(?:^|-)([0-9a-f]{8})$/.exec(label);
    if (hex && WILDCARD_SERVICES.has(registrableDomain(host))) {
      const n = parseInt(hex[1], 16);
      out.add([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'));
    }
  }
  return [...out];
}

function registrableDomain(host) {
  if (parseIp(host)) return null;
  if (isLoopbackName(host)) return 'localhost';
  const labels = host.split('.').filter((l) => l.length > 0);
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) return labels.slice(-3).join('.');
  return lastTwo;
}

function isWildcardService(host) {
  return WILDCARD_SERVICES.has(registrableDomain(host));
}

module.exports = {
  parseIp,
  normaliseIp,
  classify,
  hostOf,
  isLoopbackName,
  embeddedIps,
  registrableDomain,
  isWildcardService,
  LOOPBACK_ADDRESSES,
};
