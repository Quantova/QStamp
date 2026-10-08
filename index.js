// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { digestBytes, digestFile, ALGORITHMS } = require('./lib/hash');
const { leafHash, rootFromPath, commitment, tree } = require('./lib/merkle');
const { stamp, complete, prepare, PENDING_FORMAT } = require('./lib/stamp');
const { verify } = require('./lib/verify');
const { FORMAT, KINDS, validate } = require('./lib/receipt');
const { NETWORKS } = require('./lib/networks');

module.exports = {
  stamp,
  complete,
  verify,
  prepare,
  digestBytes,
  digestFile,
  leafHash,
  rootFromPath,
  commitment,
  tree,
  validateReceipt: validate,
  RECEIPT_FORMAT: FORMAT,
  PENDING_FORMAT,
  KINDS,
  ALGORITHMS,
  NETWORKS,
};
