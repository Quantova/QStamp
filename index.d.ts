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
  until?: number;
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
  until?: number;
}

export interface QstampError extends Error {
  code?: 'QSTAMP_PENDING' | 'QSTAMP_NOT_RECORDED' | 'QSTAMP_UNCONFIRMED' | 'QSTAMP_DISAGREEMENT' | 'QSTAMP_CHAIN_TIME' | 'QSTAMP_TRANSPORT' | 'QSTAMP_FILE';
  reason?: string;
  transient?: boolean;
  pending?: PendingStamp;
  cause?: unknown;
}

export interface EndpointEntry {
  url: string;
  ca?: string | Buffer;
  cert?: string | Buffer;
  key?: string | Buffer;
}

export interface ProofStep {
  sibling: string;
  left: boolean;
}

export interface TransactionProof {
  tx_id: string;
  height: number;
  index: number;
  transaction_root: string;
  leaf: string;
  steps: ProofStep[];
}

export interface ChainReader {
  nodeInfo(): Promise<unknown>;
  transaction(txId: string): Promise<unknown>;
  events(height: number): Promise<unknown>;
  block(height: number): Promise<unknown>;
  storageAt?(contract: string, keys: string[]): Promise<unknown>;
  finality?(height: number): Promise<unknown>;
  eventProof?(height: number, index: number): Promise<unknown>;
  transactionProof?(txId: string): Promise<TransactionProof>;
  validatorSet?(epoch: number): Promise<unknown>;
}

export interface ControlOptions {
  deadlineMs?: number;
  signal?: AbortSignal;
}

export interface EndpointOptions extends ControlOptions {
  rpc?: string | EndpointEntry | Array<string | EndpointEntry>;
  client?: ChainReader | unknown;
  clients?: Array<string | EndpointEntry | ChainReader | unknown>;
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  endpointAllowList?: string[];
}

export interface StampOptions extends EndpointOptions {
  seed: Uint8Array;
  index: number;
  records: StampRecord[];
  kind?: string | number | bigint;
  until?: number;
  network?: 'testnet';
  meter?: number;
  maxFee?: string | number;
  timeoutMs?: number;
  onPending?: (pending: PendingStamp) => void | Promise<void>;
}

export interface VerifyOptions extends EndpointOptions {
  file?: string;
  bytes?: Uint8Array;
  digest?: Bytes32;
  contract?: string;
  trustCustomContract?: boolean;
  expectedSender?: string | string[];
}

export interface VerifyCheck {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
}

export type VerifyTrust = 'finality-proof' | 'official-quorum' | 'single-endpoint' | 'custom-endpoints' | 'none';

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'invalid' | 'indeterminate' | 'unproven';
  proven: boolean;
  trust: VerifyTrust;
  trustDetail: string;
  revoked: null | false | { reason: string };
  contentChecked: boolean;
  endpoints: string[];
  officialEndpoints: boolean;
  operators: string[];
  notices: string[];
  checks: VerifyCheck[];
}

export interface NetworkEndpoint {
  url: string;
  operator: string;
  ca?: string | Buffer;
  cert?: string | Buffer;
  key?: string | Buffer;
  insecure?: true;
}

export interface RosterMember {
  id: number;
  stake: string;
  attest_pk: string;
}

export interface Network {
  name: string;
  rpc: string;
  rpcs: ReadonlyArray<NetworkEndpoint>;
  chainId: string;
  genesis: string;
  contract: string;
  genesisTime: number;
  blocks: { minPerSecond: number; maxPerSecond: number; stallSeconds: number; slack: number };
  finality: { epochBlocks: number | null; rosters: Readonly<Record<string, ReadonlyArray<RosterMember>>> };
  requireFinality?: boolean;
}

export interface CommitmentContext {
  genesis: string;
  contract: string;
  sender: string;
  kind: string;
}

export function stamp(options: StampOptions): Promise<Receipt[]>;
export interface ChainTimeOptions extends EndpointOptions {
  network?: 'testnet';
  clockSlackMs?: number;
}

export interface ChainTime {
  chainMs: number;
  hostMs: number;
  early: number;
  late: number;
  height: number;
  endpoints: string[];
  officialEndpoints: boolean;
  trust: 'official-quorum' | 'single-endpoint' | 'custom-endpoints';
}

export function complete(pending: PendingStamp, options?: EndpointOptions & { timeoutMs?: number }): Promise<Receipt[]>;
export function chainTime(options?: ChainTimeOptions): Promise<ChainTime>;
export function verify(receipt: unknown, options?: VerifyOptions): Promise<VerifyResult>;
export function isProven(result: unknown): boolean;
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
