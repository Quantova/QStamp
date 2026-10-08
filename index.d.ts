// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type DigestAlgorithm = 'sha3-256' | 'sha256';
export type Bytes32 = Uint8Array | string;

export interface StampRecord {
  digest: Bytes32;
  alg?: DigestAlgorithm;
  salt?: Bytes32;
}

export interface Receipt {
  format: 'qstamp-receipt/1';
  chain: { id: string; genesis: string };
  contract: string;
  kind: string;
  record: { alg: DigestAlgorithm; digest: string; salt: string };
  proof: { index: number; size: number; path: string[] };
  root: string;
  anchor: { tx: string; height: number; block: string; time: number; sender: string };
}

export interface PendingStamp {
  format: 'qstamp-pending/1';
  network: string;
  contract: string;
  kind: string;
  sender: string;
  tx: string;
  commitment: string;
  records: Array<{ alg: DigestAlgorithm; digest: string; salt: string }>;
}

export interface QstampError extends Error {
  code?: 'QSTAMP_PENDING' | 'QSTAMP_NOT_RECORDED';
  pending?: PendingStamp;
}

export interface StampOptions {
  seed: Uint8Array;
  index: number;
  records: StampRecord[];
  kind?: string | number | bigint;
  network?: 'testnet';
  rpc?: string;
  client?: unknown;
  meter?: number;
  maxFee?: string | number;
  timeoutMs?: number;
  onPending?: (pending: PendingStamp) => void | Promise<void>;
}

export interface VerifyOptions {
  file?: string;
  bytes?: Uint8Array;
  digest?: Bytes32;
  rpc?: string;
  client?: unknown;
  clients?: Array<string | unknown>;
  contract?: string;
  trustCustomContract?: boolean;
}

export interface VerifyCheck {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'invalid' | 'indeterminate';
  contentChecked: boolean;
  endpoints: string[];
  officialEndpoints: boolean;
  checks: VerifyCheck[];
}

export interface Network {
  name: string;
  rpc: string;
  chainId: string;
  genesis: string;
  contract: string;
}

export interface CommitmentContext {
  genesis: string;
  contract: string;
  sender: string;
  kind: string;
}

export function stamp(options: StampOptions): Promise<Receipt[]>;
export function complete(pending: PendingStamp, options?: { rpc?: string; client?: unknown; timeoutMs?: number }): Promise<Receipt[]>;
export function verify(receipt: unknown, options?: VerifyOptions): Promise<VerifyResult>;
export function prepare(records: StampRecord[]): { recs: Array<{ alg: DigestAlgorithm; digest: Buffer; salt: Buffer }>; root: Buffer; paths: Buffer[][] };
export function digestBytes(bytes: Uint8Array, alg?: DigestAlgorithm): Buffer;
export function digestFile(path: string, alg?: DigestAlgorithm): Promise<Buffer>;
export function leafHash(alg: DigestAlgorithm, digest: Buffer, salt: Buffer): Buffer;
export function rootFromPath(leaf: Buffer, index: number, size: number, path: Buffer[]): Buffer | null;
export function commitment(root: Buffer, size: number, context: CommitmentContext): Buffer;
export function tree(leafHashes: Buffer[]): { root: Buffer; paths: Buffer[][] };
export function validateReceipt(receipt: unknown): Receipt;
export const RECEIPT_FORMAT: 'qstamp-receipt/1';
export const PENDING_FORMAT: 'qstamp-pending/1';
export const KINDS: Readonly<Record<string, number>>;
export const ALGORITHMS: Readonly<Record<DigestAlgorithm, number>>;
export const NETWORKS: Readonly<Record<string, Network>>;
