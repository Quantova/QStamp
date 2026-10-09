# Qstamp

Qstamp is a post quantum time stamping SDK for the Quantova chain. It produces evidence that a record existed in an exact form no later than a stated moment, and it lets any third party confirm that evidence without trusting the party that created it.

Qstamp proves records without disclosing them. The records stay private on the systems of the organisation that holds them. Only a salted cryptographic commitment is written to the chain, and no record content, prompt, personal data or payment detail is ever published.

## What is published and what stays private

Qstamp is designed for organisations that must prove what their systems did while keeping the underlying data confidential.

The following stay on the systems of the organisation and are never sent by the SDK to Quantova Inc, to the network or to any other party.

1. The records themselves, including prompts and instructions, agent inputs and outputs, reasoning, tool calls, documents, model files, personal data and payment details.
2. The fingerprint of each record and the random salt bound to it.
3. The receipts.

The following are written to the chain, where anyone can read them.

1. One 32 byte commitment for each batch, computed from the salted fingerprints of every record in the batch.
2. The record kind, a number such as 6 for an AI agent action.
3. The ordinary data of every transaction, namely the signing account, the contract, the block, the time and the fee.

The commitment is the output of SHA3 over salted values. It cannot be reversed into any record, and because every record carries a fresh 256 bit random salt, nobody can confirm a guess about a record, even a short or predictable one. The commitment does not reveal how many records a batch holds or what they contain.

A record is disclosed only when its holder chooses to produce it, for example to a court, a regulator or an auditor, together with its receipt. The verifier then checks the record against the commitment on the chain.

Transparency in Qstamp therefore means that the proof can be inspected by anyone. It does not mean that the data is open.

## Purpose

Almost every digital signature in use today relies on elliptic curve or RSA cryptography. A sufficiently capable quantum computer will be able to forge such signatures. From that point a forged signature and a genuine one become indistinguishable, unless the genuine record can be shown to have existed before the break.

Qstamp provides that showing. Each anchored commitment is carried by a transaction signed with the Module Lattice Digital Signature Algorithm (FIPS 204, parameter set 65) and finalised by a validator committee that signs every block with the same algorithm. The Quantova chain has used these signatures from its first block, so the record of when a commitment was made does not depend on any primitive that a quantum computer is known to break.

Typical uses include financial and trading records, contracts and loan documents, regulatory filings, official registers, software releases, AI models and datasets, and records of decisions taken by AI systems.

## Cryptographic construction

1. Fingerprint. Each record is reduced to a 32 byte digest using SHA3 with a 256 bit output (FIPS 202) by default, or SHA2 with a 256 bit output (FIPS 180 revision 4) where an existing system already uses it. The algorithm is bound into the leaf so that a digest produced by one algorithm can never be presented as a digest of the other.

2. Leaf. Each digest is combined with a fresh 32 byte random salt drawn from the operating system generator. The leaf value is the SHA3 hash of the byte 0x00, the domain label QSTAMP/LEAF/V1, the algorithm identifier, the digest and the salt. The salt prevents any party who sees the chain from confirming a guess about the content of a low entropy record.

3. Batch tree. Leaves are arranged in a binary hash tree following the construction of RFC 9162 section 2.1. Interior nodes are the SHA3 hash of the byte 0x01 followed by the left and right children. Distinct leading bytes separate leaves from nodes and remove second preimage ambiguity. One batch holds up to 1048576 records.

4. Commitment. The value written to the chain is the SHA3 hash of the byte 0x02, the domain label QSTAMP/ROOT/V1, the genesis hash of the chain, the contract address, the signer address, the record kind as an unsigned 64 bit big endian integer, the batch size as an unsigned 64 bit big endian integer and the tree root. Binding all of these means the batch cannot be replayed on another chain or contract, cannot be claimed by another signer who copies the commitment from a pending transaction, and cannot have its kind, size or record positions altered after anchoring.

5. Anchoring. A single transaction calls the Qstamp contract with the commitment and a record kind, and nothing else about the batch is sent. The contract emits one event that holds the address of the signer, the commitment and the kind. The contract keeps no state, holds no funds and has no owner or upgrade path. The Quantova chain admits only contract code signed by its attested compiler, so the deployed contract cannot be replaced by altered code at the same address.

6. Receipt. Each record receives its own receipt. A receipt holds the chain identity, the contract address, the record kind, the algorithm, digest and salt, the inclusion path, the tree root and the anchoring transaction, block height, block identifier, block time and signer address. A receipt contains no part of the record.

## What a receipt establishes

When verification succeeds, the following statements hold.

1. The content presented to the verifier has exactly the digest held in the receipt.
2. That digest, with its salt and algorithm, is a leaf of a batch tree of the stated size at the stated position.
3. The commitment to that tree and size was recorded by the official Qstamp contract in the stated block, in a transaction signed by the stated address.
4. That block is final on the chain whose name and genesis hash appear in the receipt.
5. The record therefore existed in exactly this form no later than the time of that block.

## What a receipt does not establish

1. It does not show that the content is true, lawful or correct. It shows only that the content existed unchanged at a point in time.
2. It does not show that the record did not exist earlier. It sets a latest possible time, not an earliest one.
3. It does not identify a natural or legal person. The signer is a chain address, and linking an address to an organisation is a separate attestation.
4. On its own it does not make an organisation compliant with any regulation, and it is not a qualified electronic time stamp within the meaning of the eIDAS regulation unless issued through a certified trust service provider.

## Trust model of this release

The checks on the record, the salt, the inclusion path and the commitment are performed locally and depend on no outside party.

Release 0.1 then confirms the anchoring transaction, the emitted event and the block through the chain RPC interface. For these facts the verifier relies on the endpoint it queries. An endpoint operated dishonestly could report an anchor that does not exist, so a verifier should use the official endpoint, which is the default, or several endpoints operated by independent parties. Every endpoint is checked to serve the chain named in the receipt, every endpoint must agree, and the result states which endpoints were consulted and whether they were the official ones.

A later release will carry the block header, the validator finality certificate and the event inclusion proof inside each receipt. Verification will then need only the receipt, the record and the published validator set, with no network access and no trusted endpoint.

The block time is set by the proposing validator in whole seconds. Validators refuse a block whose time is more than 15 seconds ahead of their own clocks or earlier than its parent, so block time never decreases and a receipt time should be read as accurate to within about 15 seconds.

Receipts name the chain by its genesis hash. A receipt verifies only against the chain on which it was created, and a relaunched network with a new genesis cannot be used to verify it.

This release targets the Quantova test network, and test network receipts carry no evidential weight. Production use will take place on the Quantova main network once it launches.

## Confidentiality of receipts

A receipt holds the digest of its record and the salt of its leaf. Anyone who holds a receipt can test guesses about the content of a low entropy record, such as a short code or an amount. Receipts should therefore be handled with the same care as the records they describe. The command line tool writes receipts readable by their owner only.

## Installation

```
npm install @quantovainc/qstamp
```

Node 20 or later is required. The only runtime dependency is `@quantovainc/qcore`, which provides post quantum transaction signing. The commands below assume the package is installed in the current project. Outside a project, run the tool as `npx @quantovainc/qstamp` so that the scoped package published by Quantova Inc is the one that runs.

## Command line use

Compute fingerprints.

```
qstamp hash report.pdf ledger.csv
```

Stamp one or more files in a single transaction. The key file holds a 32 byte seed as 64 hexadecimal characters and must be readable only by its owner.

```
qstamp stamp report.pdf ledger.csv --seed-file ./signer.key --index 0 --kind financial_record
```

Each file receives a receipt named after it with the suffix `.qstamp.json`. Every receipt file is reserved before anything is signed, so a stamp is never paid for without a place to record it. Two inputs that would share one receipt name are refused, and receipts are never written through a symbolic link. Every receipt and pending file is written to a new private file and then moved into place, so an existing receipt replaced with `--force` stays intact until its replacement is complete. The `complete` command writes only files whose names end in `.qstamp.json` and never replaces an existing receipt unless `--force` is given.

If the transaction is accepted but its outcome cannot be confirmed, the tool keeps a private pending file and names it. The pending file also holds the records and salts when the network fails during submission, so that no stamp is ever lost. The receipts are then recovered with the following command, adding `--tx` with the transaction id when the pending file does not yet name one.

```
qstamp complete qstamp-pending-1760000000000-a1b2c3d4.json
```

Verify a receipt against its record. Verification requires the record or its digest, and it may consult several endpoints.

```
qstamp verify report.pdf.qstamp.json --file report.pdf --rpc https://rpc-testnet.quantova.org
```

The command exits with status 0 when the receipt is valid, 1 when it is invalid or cannot be read and 2 only when it could not be evaluated, for example because no endpoint could be reached. Usage errors exit with status 64. An unreachable endpoint never produces a valid result. Unknown or misspelt options are refused before any action is taken. Text received from an endpoint is stripped of control characters before it is shown, and an endpoint listed twice is consulted once.

## Programmatic use

```js
const qstamp = require('@quantovainc/qstamp');

const digest = await qstamp.digestFile('report.pdf');
const [receipt] = await qstamp.stamp({
  seed,
  index: 0,
  kind: 'financial_record',
  records: [{ digest }],
});

const result = await qstamp.verify(receipt, { file: 'report.pdf' });
```

The seed must be supplied as a `Uint8Array` of 32 bytes so that the caller can wipe it. Text seeds are refused because text cannot be erased from memory. The SDK signs from a private copy and overwrites that copy with zeros as soon as the transaction is signed. The underlying signing library also holds the seed briefly in its own memory, which cannot be wiped from JavaScript.

The `verify` result reports a status of valid, invalid or indeterminate, lists every check with its outcome and reason, states whether the record itself was checked and names the endpoints consulted. A receipt is never reported valid unless the record or its digest was supplied and matched.

Every error raised after the transaction is accepted carries the pending batch in a plain form that can be stored. An error raised while the network was being contacted to submit the transaction carries the pending batch as well, with the code `QSTAMP_UNCONFIRMED` and no transaction id, so that its salts are never lost. `complete` finishes the receipts from that pending batch once the transaction is final. The `onPending` option receives the pending batch before the SDK waits for finality, so that an application can store it first.

Receipts produced by an institution through its own deployment of a Qstamp contract template are verified by passing that contract address together with `trustCustomContract` set to true. Without that flag the verifier accepts only the official contract of each network.

## Record kinds

The kind is an unsigned 64 bit value recorded on the chain with each commitment. Named kinds are record 0, file 1, document 2, software release 3, AI model 4, AI dataset 5, AI agent action 6, AI output 7, wallet binding 8, financial record 9 and public record 10, where public record refers to records held by public bodies and does not mean that the record is published. Other values are available for private schemes.

## Independent verification procedure

An auditor can verify a receipt without this SDK by following these steps.

1. Compute the digest of the record with the algorithm named in the receipt and compare it with the receipt digest.
2. Compute the leaf from the byte 0x00, the label QSTAMP/LEAF/V1, the algorithm identifier (1 for SHA3 with a 256 bit output and 2 for SHA2 with a 256 bit output), the digest and the salt.
3. Recompute the tree root from the leaf, the position, the batch size and the inclusion path using the procedure of RFC 9162 section 2.1.3.2, and compare it with the receipt root.
4. Compute the commitment from the byte 0x02, the label QSTAMP/ROOT/V1, the genesis hash, the contract address bytes, the signer address bytes, the kind, the batch size and the root.
5. Query the chain for the anchoring transaction and confirm it is final, was signed by the stated address, was sent to the official contract at the stated height and block, and carries the commitment and kind in its call data.
6. Query the events at that height and confirm the official contract emitted an event with selector 5a110849 whose data is the signer address, the commitment and the kind.
7. Query the block at that height and confirm its identifier and time.

## Network

The Quantova test network is named `Q-test-net-1` with genesis hash `ca91e093bb8de33e90db52d7c89876597d14760703793ea7211929e73e613062`. The Qstamp contract on that network is at `Q1D6TZFRL203P3DFAFVUPZUHGUCM4EWGH6063XNS42VA5235RNQWXS7FXEWX`. The public endpoint is `https://rpc-testnet.quantova.org`.

## Licence

Qstamp is created and owned by Quantova Inc. It is licensed under the Apache License 2.0 or the MIT licence, at your option. The full texts are in the files `LICENSE-APACHE` and `LICENSE-MIT`, and the notice is in `NOTICE`.
